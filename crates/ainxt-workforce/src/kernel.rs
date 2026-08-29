// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! **The OS process model** — roles run as *processes* on the runtime kernel (AINXT_OS §2 diagram;
//! WORKFORCE_AND_OS §4: "Kernel = the Runtime; Processes = roles running on the runtime").
//!
//! The AiNxt-OS framing maps operating-system concepts onto the runtime: the **kernel** is the
//! runtime, and a **process** is a *published* role running on it. This module is the declarative,
//! deterministic bridge that expresses that mapping as real objects a runtime scheduler binds to: a
//! [`Kernel`] holds a process table; [`Kernel::spawn`] admits a [`PublishedRole`] as a [`RoleProcess`]
//! with a [`Pid`] and a lifecycle [`ProcessState`].
//!
//! The safety invariant is type-level and inherited from the Breaker gate: `spawn` takes a
//! [`PublishedRole`] *by value*, and a `PublishedRole` can only be minted by
//! [`crate::breaker::publish`]. So **only a Breaker-passed, governed role can ever become a running
//! process** — you cannot schedule an un-tested worker onto the kernel, by construction.
//!
//! Binding this table onto the live runtime scheduler / event-bus (async execution, real IPC) is a
//! call-site in the reserved `ainxt-runtimed` crate; this module is the clean entrypoint that binding
//! drives. It is pure: no async, no clock, no threads — every scheduling decision here is a
//! deterministic state transition.

use std::collections::BTreeMap;

use crate::role::PublishedRole;

/// A process identifier assigned by the kernel on spawn (monotonic, deterministic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(pub u64);

impl std::fmt::Display for Pid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pid:{}", self.0)
    }
}

/// The lifecycle state of a role-process — the OS process-state model applied to a digital worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Admitted, waiting for the scheduler to dispatch it.
    Ready,
    /// Currently executing a task on the runtime.
    Running,
    /// Waiting on a human (a HITL approval / escalation) — the OS "blocked on I/O" analogue.
    Blocked,
    /// Finished / retired; no longer schedulable.
    Terminated,
}

/// Why a kernel operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelError {
    /// No process with that pid exists in the table.
    NoSuchProcess(Pid),
    /// The requested state transition is not legal from the process's current state.
    IllegalTransition {
        pid: Pid,
        from: ProcessState,
        to: ProcessState,
    },
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KernelError::NoSuchProcess(p) => write!(f, "no such process {p}"),
            KernelError::IllegalTransition { pid, from, to } => {
                write!(f, "{pid}: illegal transition {from:?} -> {to:?}")
            }
        }
    }
}
impl std::error::Error for KernelError {}

/// A running (or runnable) role — a *process* on the kernel. Wraps the governed [`PublishedRole`]; its
/// existence proves the role cleared the Breaker gate.
#[derive(Debug)]
pub struct RoleProcess {
    pid: Pid,
    role: PublishedRole,
    state: ProcessState,
}

impl RoleProcess {
    pub fn pid(&self) -> Pid {
        self.pid
    }
    pub fn state(&self) -> ProcessState {
        self.state
    }
    pub fn role(&self) -> &PublishedRole {
        &self.role
    }
    pub fn role_id(&self) -> &str {
        self.role.id()
    }
}

/// The runtime kernel's process table for digital workers. Deterministic: pids are assigned in spawn
/// order and all transitions are pure.
#[derive(Debug, Default)]
pub struct Kernel {
    next_pid: u64,
    table: BTreeMap<Pid, RoleProcess>,
}

impl Kernel {
    pub fn new() -> Self {
        Kernel {
            next_pid: 1,
            table: BTreeMap::new(),
        }
    }

    /// **Spawn a role as a process.** Consumes a [`PublishedRole`] (by value) — the only way to get one
    /// is through the Breaker publish gate, so an un-tested role can never be scheduled. Returns the
    /// assigned [`Pid`]; the process starts [`ProcessState::Ready`].
    pub fn spawn(&mut self, role: PublishedRole) -> Pid {
        let pid = Pid(self.next_pid);
        self.next_pid += 1;
        self.table.insert(
            pid,
            RoleProcess {
                pid,
                role,
                state: ProcessState::Ready,
            },
        );
        pid
    }

    /// Dispatch a Ready process to Running (the scheduler picking it up).
    pub fn dispatch(&mut self, pid: Pid) -> Result<(), KernelError> {
        self.transition(pid, ProcessState::Running, &[ProcessState::Ready])
    }

    /// Block a Running process awaiting a human (HITL / escalation).
    pub fn block(&mut self, pid: Pid) -> Result<(), KernelError> {
        self.transition(pid, ProcessState::Blocked, &[ProcessState::Running])
    }

    /// Wake a Blocked process back to Ready once the human responded.
    pub fn wake(&mut self, pid: Pid) -> Result<(), KernelError> {
        self.transition(pid, ProcessState::Ready, &[ProcessState::Blocked])
    }

    /// Yield a Running process back to Ready (cooperative scheduling).
    pub fn yield_back(&mut self, pid: Pid) -> Result<(), KernelError> {
        self.transition(pid, ProcessState::Ready, &[ProcessState::Running])
    }

    /// Terminate a process from any live state (retire / pause / rollback, AINXT_OS §4 Step 10).
    pub fn terminate(&mut self, pid: Pid) -> Result<(), KernelError> {
        self.transition(
            pid,
            ProcessState::Terminated,
            &[
                ProcessState::Ready,
                ProcessState::Running,
                ProcessState::Blocked,
            ],
        )
    }

    fn transition(
        &mut self,
        pid: Pid,
        to: ProcessState,
        allowed_from: &[ProcessState],
    ) -> Result<(), KernelError> {
        let proc = self
            .table
            .get_mut(&pid)
            .ok_or(KernelError::NoSuchProcess(pid))?;
        if !allowed_from.contains(&proc.state) {
            return Err(KernelError::IllegalTransition {
                pid,
                from: proc.state,
                to,
            });
        }
        proc.state = to;
        Ok(())
    }

    pub fn get(&self, pid: Pid) -> Option<&RoleProcess> {
        self.table.get(&pid)
    }
    pub fn state_of(&self, pid: Pid) -> Option<ProcessState> {
        self.table.get(&pid).map(|p| p.state)
    }
    /// Pids the scheduler may currently dispatch (Ready), in deterministic pid order.
    pub fn runnable(&self) -> Vec<Pid> {
        self.table
            .iter()
            .filter(|(_, p)| p.state == ProcessState::Ready)
            .map(|(pid, _)| *pid)
            .collect()
    }
    /// All live (non-terminated) processes.
    pub fn live_count(&self) -> usize {
        self.table
            .values()
            .filter(|p| p.state != ProcessState::Terminated)
            .count()
    }
    pub fn process_count(&self) -> usize {
        self.table.len()
    }
}
