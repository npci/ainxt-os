// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Pre-templated breach-report drafting (§2.4; FI-08) — spend the 6-hour budget on judgment, not
//! data-gathering.
//!
//! The report **templates** (CERT-In / DPDP-to-Board / DPDP-to-principal / RBI) are control-plane
//! definitions (git, Q2): PII-free forms with `{{placeholder}}` slots, versioned and owned by
//! Legal/DPO. A [`TemplateStore`] holds them. [`draft_report`] fills a template *from the incident
//! register's structured facts + the Event-Log evidence slice*, producing a [`ReportDraft`] within
//! (logical) minutes of t0. The draft is **never auto-filed** — filing is the human legal act
//! ([`crate::IncidentRegister::record_filing`] records it after the human files). Any placeholder the
//! runtime cannot fill is surfaced in [`ReportDraft::unfilled`] so the human knows exactly what
//! judgment is still required — never silently blank.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Incident, IncidentRegister};

/// The statutory report kind a template drafts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReportKind {
    CertIn,
    DpdpBoard,
    DpdpDataPrincipal,
    RbiOutsourcing,
}

impl ReportKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReportKind::CertIn => "cert-in",
            ReportKind::DpdpBoard => "dpdp-board",
            ReportKind::DpdpDataPrincipal => "dpdp-data-principal",
            ReportKind::RbiOutsourcing => "rbi-outsourcing",
        }
    }
}

/// A control-plane report template: a versioned form with `{{placeholder}}` slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub kind: ReportKind,
    /// The control-plane version string (a git SHA / semantic version). Recorded on the filing so
    /// "which form did we file against" is answerable (§2.4).
    pub template_version: String,
    /// The template body with `{{field}}` placeholders.
    pub body: String,
}

impl ReportTemplate {
    pub fn new(kind: ReportKind, template_version: &str, body: &str) -> Self {
        Self {
            kind,
            template_version: template_version.to_string(),
            body: body.to_string(),
        }
    }
}

/// The control-plane template store (§2.4). One template per [`ReportKind`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateStore {
    templates: BTreeMap<ReportKind, ReportTemplate>,
}

impl TemplateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register/replace a template (chainable).
    pub fn add(&mut self, template: ReportTemplate) -> &mut Self {
        self.templates.insert(template.kind, template);
        self
    }

    pub fn get(&self, kind: ReportKind) -> Option<&ReportTemplate> {
        self.templates.get(&kind)
    }

    /// Generic default template store — empty. Use this as the OSS baseline;
    /// add templates via `add()` for your jurisdiction's regulatory requirements.
    pub fn generic_default() -> Self {
        Self::new()
    }

    /// India regulatory default: minimal illustrative CERT-In and DPDP-board templates
    /// (PII-free forms; the real forms are Legal/DPO-owned git artifacts).
    /// Enough for the drafting mechanism to be exercised end-to-end.
    pub fn india_regulatory_default() -> Self {
        let mut s = Self::new();
        s.add(ReportTemplate::new(
            ReportKind::CertIn,
            "cert-in-v1",
            "CERT-In Incident Report\n\
             Incident ID: {{incident_id}}\n\
             Class: {{class}}\n\
             Time of first notice (t0): {{t0}}\n\
             Systems involved: {{systems}}\n\
             Affected data classes: {{data_classes}}\n\
             Estimated affected principals: {{principals}}\n\
             Control-plane SHA: {{control_plane_sha}}\n\
             Evidence events: {{evidence_count}}\n",
        ));
        s.add(ReportTemplate::new(
            ReportKind::DpdpBoard,
            "dpdp-board-v1",
            "DPDP Breach Report to the Board\n\
             Incident ID: {{incident_id}}\n\
             Class: {{class}}\n\
             Affected principals: {{principals}}\n\
             Data classes: {{data_classes}}\n\
             Control-plane SHA: {{control_plane_sha}}\n",
        ));
        s
    }

    /// Deprecated alias for [`india_regulatory_default`](TemplateStore::india_regulatory_default).
    /// Use `india_regulatory_default()` in new code.
    #[deprecated(since = "1.0.0", note = "use `india_regulatory_default()` instead")]
    pub fn india_default() -> Self {
        Self::india_regulatory_default()
    }
}

/// The output of drafting: the filled body, the template version used, and the list of placeholders
/// the runtime could not fill from structured facts (the human must complete these).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportDraft {
    pub kind: ReportKind,
    pub template_version: String,
    pub body: String,
    /// Placeholders that had no known value — surfaced, never silently blanked.
    pub unfilled: Vec<String>,
}

/// Build the structured-fact substitution map from an incident + its evidence slice.
fn fields(incident: &Incident, evidence_count: usize) -> BTreeMap<&'static str, String> {
    let mut m = BTreeMap::new();
    m.insert("incident_id", incident.id.clone());
    m.insert("class", incident.class.as_str().to_string());
    m.insert("t0", incident.t0.to_string());
    m.insert("systems", incident.systems_involved.join(", "));
    m.insert(
        "data_classes",
        incident
            .affected_data_classes
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );
    m.insert(
        "principals",
        incident.affected_principal_estimate.to_string(),
    );
    m.insert("control_plane_sha", incident.control_plane_sha.clone());
    m.insert("evidence_count", evidence_count.to_string());
    m
}

/// Substitute every `{{field}}` in `body` from `values`; collect any placeholder with no value.
fn substitute(body: &str, values: &BTreeMap<&'static str, String>) -> (String, Vec<String>) {
    let mut out = String::with_capacity(body.len());
    let mut unfilled = Vec::new();
    let bytes = body.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        if i + 1 < n && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(rel) = body[i + 2..].find("}}") {
                let name = &body[i + 2..i + 2 + rel];
                let key = name.trim();
                match values.get(key) {
                    Some(v) => out.push_str(v),
                    None => {
                        // Unknown placeholder: keep it visible AND flag it.
                        out.push_str("{{");
                        out.push_str(name);
                        out.push_str("}}");
                        if !unfilled.contains(&key.to_string()) {
                            unfilled.push(key.to_string());
                        }
                    }
                }
                i = i + 2 + rel + 2;
                continue;
            }
        }
        // Not a placeholder start; copy this byte (safe: we only split on ASCII '{'/'}').
        let ch_len = utf8_len(bytes[i]);
        out.push_str(&body[i..i + ch_len]);
        i += ch_len;
    }
    (out, unfilled)
}

/// The byte length of a UTF-8 sequence given its lead byte.
fn utf8_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead >> 5 == 0b110 {
        2
    } else if lead >> 4 == 0b1110 {
        3
    } else if lead >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

/// FI-08: draft a statutory report for `incident_id` using `store`'s template for `kind`, filled from
/// the register's structured facts + the incident's Event-Log evidence slice. Returns `None` if the
/// incident is unknown or no template exists for the kind. The draft is **never filed** by this call.
pub fn draft_report(
    register: &IncidentRegister,
    incident_id: &str,
    kind: ReportKind,
    store: &TemplateStore,
) -> Option<ReportDraft> {
    let incident = register.incident(incident_id)?;
    let template = store.get(kind)?;
    let evidence_count = register
        .events()
        .iter()
        .filter(|e| e.incident_id == incident_id)
        .count();
    let values = fields(incident, evidence_count);
    let (body, unfilled) = substitute(&template.body, &values);
    Some(ReportDraft {
        kind,
        template_version: template.template_version.clone(),
        body,
        unfilled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArmingPolicy, IncidentCandidate, IncidentRegister};
    use ainxt_types::DataClass;

    fn seeded() -> (IncidentRegister, String) {
        let mut reg = IncidentRegister::new(ArmingPolicy::india_regulatory_default());
        let cand =
            IncidentCandidate::from_compliance_egress(100, "sha-live-77", DataClass::Pii, 12)
                .with_system("cloud-route-claude");
        let id = reg.open_from(cand, 100);
        (reg, id)
    }

    #[test]
    fn gap_ainxt_incident_fi08_draft_fills_template_from_incident_facts() {
        // §2.6 / §2.4: a draft report exists with the incident's structured facts filled — no known
        // placeholder is left blank, and the template version is recorded for the eventual filing.
        let (reg, id) = seeded();
        let store = TemplateStore::india_regulatory_default();
        let draft = draft_report(&reg, &id, ReportKind::CertIn, &store).unwrap();

        assert_eq!(draft.template_version, "cert-in-v1");
        assert!(draft.body.contains(&id), "incident id must be filled");
        assert!(draft.body.contains("personal-data-breach"), "class filled");
        assert!(draft.body.contains("cloud-route-claude"), "systems filled");
        assert!(
            draft.body.contains("sha-live-77"),
            "control-plane SHA filled"
        );
        assert!(draft.body.contains("12"), "principal estimate filled");
        // All known placeholders were substituted — none of the {{...}} tokens for known fields remain.
        assert!(!draft.body.contains("{{incident_id}}"));
        assert!(!draft.body.contains("{{class}}"));
        assert!(!draft.body.contains("{{control_plane_sha}}"));
        assert!(
            draft.unfilled.is_empty(),
            "no unknown fields: {:?}",
            draft.unfilled
        );
    }

    #[test]
    fn gap_ainxt_incident_fi08_unknown_placeholder_is_surfaced_not_silently_blanked() {
        // A template referencing a field the runtime cannot fill surfaces it in `unfilled` and leaves
        // the placeholder visible — the human knows exactly what judgment is still required.
        let (reg, id) = seeded();
        let mut store = TemplateStore::new();
        store.add(ReportTemplate::new(
            ReportKind::RbiOutsourcing,
            "rbi-v1",
            "Incident {{incident_id}} — remediation owner: {{remediation_owner}}",
        ));
        let draft = draft_report(&reg, &id, ReportKind::RbiOutsourcing, &store).unwrap();
        assert!(draft.body.contains(&id));
        assert!(
            draft.body.contains("{{remediation_owner}}"),
            "unknown kept visible"
        );
        assert_eq!(draft.unfilled, vec!["remediation_owner".to_string()]);
    }

    #[test]
    fn gap_ainxt_incident_fi08_missing_template_or_incident_returns_none() {
        let (reg, id) = seeded();
        let store = TemplateStore::new(); // empty
        assert!(draft_report(&reg, &id, ReportKind::CertIn, &store).is_none());
        let store = TemplateStore::india_regulatory_default();
        assert!(draft_report(&reg, "no-such-incident", ReportKind::CertIn, &store).is_none());
    }
}
