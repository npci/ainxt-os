// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! Round-12 (loop-teams-longhorizon gap 5): a GPU-fleet **QoS workload class** + a
//! **preemptible-low-priority** tier + an **elastic fan-out** admission policy for program Runs. The
//! parallel fan-out width is no longer a blind fixed ceiling: it is decided against the live fleet
//! capacity and the Run's class, so a batch migration bursts into spare capacity yet always leaves
//! interactive headroom, and a low-priority sweep yields entirely when higher-priority work is queued.
//!
//! Infra note: the LIVE GPU fleet (vLLM batching, real GPU counts, in-flight-kernel preemption) is
//! infrastructure the deployment wires behind this decision (infra-gated); the *admission decision*
//! this test exercises is the pure policy that was missing.

use ainxt_planner::qos::{ElasticFanoutPolicy, FleetCapacity, WorkloadClass};

#[test]
fn r12_gpu_qos_elastic_fanout() {
    let policy = ElasticFanoutPolicy::default();

    // A fleet with 10 slots, 2 busy (8 free), keeping 3 free for interactive traffic.
    let idle = FleetCapacity::new(10, 2).with_interactive_reserve(3);

    // Interactive: may consume all free capacity, including the reserve (it IS interactive traffic).
    assert_eq!(policy.admit(20, WorkloadClass::Interactive, &idle), 8);

    // Batch: bursts into free capacity but leaves the interactive headroom (8 - 3 = 5).
    assert_eq!(policy.admit(20, WorkloadClass::Batch, &idle), 5);
    // ...and never admits more than the ready width.
    assert_eq!(policy.admit(2, WorkloadClass::Batch, &idle), 2);

    // Preemptible low-priority: uses only slack (also 5 when idle)...
    assert_eq!(
        policy.admit(9, WorkloadClass::PreemptibleLowPriority, &idle),
        5
    );
    // ...but yields ENTIRELY when higher-priority work is queued.
    let busy = idle.with_higher_priority_queued(true);
    assert_eq!(
        policy.admit(9, WorkloadClass::PreemptibleLowPriority, &busy),
        0
    );
    // Batch also holds its next wave while higher-priority work is queued (yields, not preempted).
    assert_eq!(policy.admit(9, WorkloadClass::Batch, &busy), 0);
    // Interactive is never held.
    assert_eq!(policy.admit(4, WorkloadClass::Interactive, &busy), 4);

    // Only the low-priority class is preemptible.
    assert!(WorkloadClass::PreemptibleLowPriority.is_preemptible());
    assert!(!WorkloadClass::Batch.is_preemptible());
    assert!(!WorkloadClass::Interactive.is_preemptible());

    // A hard per-wave ceiling caps even a huge idle fleet (bounds blast radius / cost).
    let huge = FleetCapacity::new(1000, 0);
    assert_eq!(
        ElasticFanoutPolicy::new(8).admit(500, WorkloadClass::Batch, &huge),
        8
    );

    // A full fleet admits nothing.
    let full = FleetCapacity::new(4, 4);
    assert_eq!(policy.admit(10, WorkloadClass::Interactive, &full), 0);

    // Class ordering reflects shed priority (cheaper-to-shed is "greater").
    assert!(WorkloadClass::Interactive < WorkloadClass::Batch);
    assert!(WorkloadClass::Batch < WorkloadClass::PreemptibleLowPriority);
}
