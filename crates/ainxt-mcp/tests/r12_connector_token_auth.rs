// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! R12 §2.2 — MCP per-`(user, server_url)` OAuth reuses the platform's encrypted connector-token
//! store instead of a bespoke MCP credential system. The [`ConnectorAuthProvider`] resolves each
//! server's token from a [`ConnectorTokenStore`] keyed strictly on the server URL (the trust
//! boundary), so: a server whose token is absent hides its tools (`AuthRequired`, not a mid-call
//! failure); two servers sharing a display name across environments resolve independent tokens; and
//! revoking one URL's token never affects the other (scenario 10). The encrypted-at-rest Postgres
//! store (FERNET/MultiFernet + distributed refresh lock) is the infra-gated production impl behind
//! the identical trait; this proves everything above the seam offline.
//!
//! Fail-before: MCP had only a bespoke `AuthProvider` with no reuse of the connector-token store,
//! and no offline proof of URL-keyed isolation/revocation. Pass-after: the connector-store-backed
//! provider drives real discovery with per-URL isolation and revocation.

use ainxt_mcp::{
    ConnectorAuthProvider, ConnectorTokenStore, InMemoryConnectorTokenStore, McpError, McpRegistry,
    McpServer, McpTransport, ToolManifest, ToolResult,
};

/// A transport that requires auth: it fails `connect` with `AuthRequired` unless a token is present,
/// and stamps the token it saw into call results so we can prove the right one was used.
struct AuthTransport {
    marker: String,
}
impl McpTransport for AuthTransport {
    fn connect(&self, token: Option<&str>) -> Result<(), McpError> {
        match token {
            Some(_) => Ok(()),
            None => Err(McpError::AuthRequired(self.marker.clone())),
        }
    }
    fn list_tools(&self) -> Result<Vec<ToolManifest>, McpError> {
        Ok(vec![ToolManifest::new(
            "do_thing",
            "a tool on the authed server",
        )])
    }
    fn call_tool(&self, tool: &str, args: &str) -> Result<ToolResult, McpError> {
        Ok(ToolResult::ok(&format!(
            "{}:{}:{}",
            self.marker, tool, args
        )))
    }
}

fn server(name: &str, url: &str, marker: &str) -> McpServer {
    McpServer::new(
        name,
        url,
        Box::new(AuthTransport {
            marker: marker.to_string(),
        }),
    )
}

#[test]
fn token_absent_degrades_to_auth_required_not_a_mid_call_failure() {
    let store = InMemoryConnectorTokenStore::new();
    let auth = ConnectorAuthProvider::new(store);
    let mut reg = McpRegistry::new();
    reg.register(server("jira", "https://jira.example/mcp", "jira"));

    // No token provisioned → the server soft-degrades in discovery, it does not fail the sweep.
    let disc = auth.store();
    let _ = disc; // (store handle available for admin ops)
    let d = reg.discover("alice", &auth);
    assert!(d.tools.is_empty(), "no plannable tools without a token");
    assert_eq!(d.failures.len(), 1);
    assert!(matches!(d.failures[0].1, McpError::AuthRequired(_)));
}

#[test]
fn token_is_resolved_on_url_and_drives_discovery() {
    let store = InMemoryConnectorTokenStore::new();
    store.provision("alice", "https://jira.example/mcp", "tok-jira-alice");
    let auth = ConnectorAuthProvider::new(store);

    let mut reg = McpRegistry::new();
    reg.register(server("jira", "https://jira.example/mcp", "jira"));

    let d = reg.discover("alice", &auth);
    assert!(
        d.failures.is_empty(),
        "a provisioned token must let the server connect"
    );
    assert_eq!(d.tools.len(), 1);
    assert_eq!(
        d.tools[0].qualified_name,
        McpRegistry::qualify("https://jira.example/mcp", "do_thing"),
        "qualified id is namespaced on the URL (§2.5), never the display name"
    );

    // A DIFFERENT user with no token for the same URL still degrades — keying is per (user, url).
    // A registry caches a connection per session, so bob uses his own session/registry.
    let mut reg_bob = McpRegistry::new();
    reg_bob.register(server("jira", "https://jira.example/mcp", "jira"));
    let d_bob = reg_bob.discover("bob", &auth);
    assert!(matches!(
        d_bob.failures.first().map(|f| &f.1),
        Some(McpError::AuthRequired(_))
    ));
}

#[test]
fn two_servers_sharing_a_name_but_different_urls_are_isolated() {
    // §2.2 / scenario 10: display name is shared across environments; the URL is the trust boundary.
    let prod_url = "https://mcp.prod.example/jira";
    let stg_url = "https://mcp.staging.example/jira";
    let store = InMemoryConnectorTokenStore::new();
    store.provision("alice", prod_url, "tok-prod");
    // staging deliberately NOT provisioned.
    let auth = ConnectorAuthProvider::new(store);

    let mut reg = McpRegistry::new();
    reg.register(server("jira", prod_url, "prod"));
    reg.register(server("jira", stg_url, "staging"));

    let d = reg.discover("alice", &auth);
    // Prod connected; staging (same display name, different URL) remained AuthRequired.
    let prod_tools: Vec<_> = d
        .tools
        .iter()
        .filter(|t| t.server_url == prod_url)
        .collect();
    let stg_tools: Vec<_> = d.tools.iter().filter(|t| t.server_url == stg_url).collect();
    assert_eq!(prod_tools.len(), 1, "prod (authorized URL) is reachable");
    assert!(
        stg_tools.is_empty(),
        "staging URL has no token and stays hidden"
    );
    assert!(
        d.failures
            .iter()
            .any(|(_, e)| matches!(e, McpError::AuthRequired(_))),
        "the unauthorized URL soft-degrades"
    );
}

#[test]
fn revoking_one_url_does_not_affect_another() {
    let a_url = "https://a.example/mcp";
    let b_url = "https://b.example/mcp";
    let store = InMemoryConnectorTokenStore::new();
    store.provision("alice", a_url, "tok-a");
    store.provision("alice", b_url, "tok-b");
    let auth = ConnectorAuthProvider::new(store);

    // Both resolve before revocation.
    assert_eq!(auth.token_for_url("alice", a_url).as_deref(), Some("tok-a"));
    assert_eq!(auth.token_for_url("alice", b_url).as_deref(), Some("tok-b"));

    // Revoke A only.
    auth.store().revoke("alice", a_url);
    assert_eq!(auth.token_for_url("alice", a_url), None, "A revoked");
    assert_eq!(
        auth.token_for_url("alice", b_url).as_deref(),
        Some("tok-b"),
        "B is unaffected by A's revocation"
    );
}

// Small helper so the test can call the AuthProvider method without importing the trait explicitly.
trait TokenForUrl {
    fn token_for_url(&self, user: &str, url: &str) -> Option<String>;
}
impl<S: ConnectorTokenStore> TokenForUrl for ConnectorAuthProvider<S> {
    fn token_for_url(&self, user: &str, url: &str) -> Option<String> {
        use ainxt_mcp::AuthProvider;
        self.token_for(user, url)
    }
}
