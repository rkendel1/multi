//! End-to-end control plane test: modify authority on live running application.
//!
//! The killer test case for PR5: proves that changes to live authority take
//! effect immediately without application restart.

use appport_auth_mesh_boundary::{Approval, AuthorityChange, BindingMode, Method};
use saas_basic::bootstrap::bootstrap;

#[test]
fn killer_test_route_protection_without_restart() {
    // Setup: Create a deployment (which includes the running runtime)
    let deployment = bootstrap(BindingMode::Embedded).expect("bootstrap deployment");
    let runtime = &deployment.runtime;

    // 1. INITIAL STATE: Verify no protection on POST /invoices
    println!("\n=== Step 1: Verify initial state (no protection) ===");
    let protection = runtime.get_route_protection(&Method::Post, "/invoices");
    assert_eq!(protection, None, "POST /invoices should start unprotected");
    println!("✓ POST /invoices is initially unprotected");

    // 2. PROPOSE: Protect POST /invoices with capability "invoice.create"
    println!("\n=== Step 2: Propose protection ===");
    let change = AuthorityChange::ProtectRoute {
        method: Method::Post,
        path: "/invoices".to_string(),
        capability: "invoice.create".to_string(),
    };

    let proposal = runtime.propose_change(change).expect("propose change");
    println!("Proposal revision: {}", proposal.revision);

    // Verify preview shows the change
    assert!(
        !proposal
            .preview
            .before
            .route_protection
            .iter()
            .any(|(r, _)| r.method == Method::Post && r.path == "/invoices"),
        "before: POST /invoices should be unprotected"
    );

    assert!(
        proposal
            .preview
            .after
            .route_protection
            .iter()
            .any(|(r, p)| {
                r.method == Method::Post
                    && r.path == "/invoices"
                    && p.capability.as_ref().is_some_and(|c| c == "invoice.create")
            }),
        "after: POST /invoices should require invoice.create"
    );
    println!("✓ Preview shows before/after");

    // 3. APPLY: Apply the change
    println!("\n=== Step 3: Apply protection ===");
    let approval = Approval::for_proposal(&proposal);
    let change_id = runtime
        .apply_change(proposal, approval)
        .expect("apply change");
    println!("Applied change: {}", change_id);

    // 4. CRITICAL: Verify protection is now live (without restart)
    println!("\n=== Step 4: Verify protection is live ===");
    let protection = runtime.get_route_protection(&Method::Post, "/invoices");
    assert_eq!(
        protection,
        Some("invoice.create".to_string()),
        "POST /invoices should now require invoice.create"
    );
    println!("✓ Protection is live immediately (no restart)");

    // 5. Verify GET /invoices is still unprotected
    println!("\n=== Step 5: Verify other methods unaffected ===");
    let protection = runtime.get_route_protection(&Method::Get, "/invoices");
    assert_eq!(
        protection, None,
        "GET /invoices should still be unprotected"
    );
    println!("✓ GET /invoices remains unprotected");

    // 6. CHANGE: Unprotect the route
    println!("\n=== Step 6: Unprotect route ===");
    let unprotect = AuthorityChange::UnprotectRoute {
        method: Method::Post,
        path: "/invoices".to_string(),
    };

    let proposal2 = runtime
        .propose_change(unprotect)
        .expect("propose unprotect");
    let approval2 = Approval::for_proposal(&proposal2);
    runtime
        .apply_change(proposal2, approval2)
        .expect("apply unprotect");

    // Verify protection is removed (without restart)
    let protection = runtime.get_route_protection(&Method::Post, "/invoices");
    assert_eq!(
        protection, None,
        "POST /invoices should be unprotected again"
    );
    println!("✓ Protection removed immediately (no restart)");

    println!("\n=== ✓ KILLER TEST PASSED ===");
    println!("Proven: Authority changes take effect immediately");
}

#[test]
fn multiple_routes_independently_protected() {
    let deployment = bootstrap(BindingMode::Embedded).expect("bootstrap deployment");
    let runtime = &deployment.runtime;

    // Protect multiple routes independently
    let routes = vec![
        (Method::Post, "/invoices", "invoice.create"),
        (Method::Patch, "/invoices", "invoice.update"),
        (Method::Post, "/orders", "order.create"),
    ];

    for (method, path, capability) in routes {
        let change = AuthorityChange::ProtectRoute {
            method,
            path: path.to_string(),
            capability: capability.to_string(),
        };

        let proposal = runtime.propose_change(change).expect("propose");
        let approval = Approval::for_proposal(&proposal);
        runtime.apply_change(proposal, approval).expect("apply");
    }

    // Verify each is independently protected
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        Some("invoice.create".to_string())
    );
    assert_eq!(
        runtime.get_route_protection(&Method::Patch, "/invoices"),
        Some("invoice.update".to_string())
    );
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/orders"),
        Some("order.create".to_string())
    );
    // Other methods should not be protected
    assert_eq!(
        runtime.get_route_protection(&Method::Get, "/invoices"),
        None
    );
    assert_eq!(
        runtime.get_route_protection(&Method::Delete, "/invoices"),
        None
    );
}

#[test]
fn state_survives_multiple_sequential_changes() {
    let deployment = bootstrap(BindingMode::Embedded).expect("bootstrap deployment");
    let runtime = &deployment.runtime;

    let mut revisions = vec![];
    let mut prev_revision = 0u64;

    // Apply 10 sequential changes
    for i in 0..10 {
        let change = AuthorityChange::ProtectRoute {
            method: Method::Post,
            path: format!("/resource{}", i),
            capability: format!("resource{}.create", i),
        };

        let proposal = runtime.propose_change(change).expect("propose");
        let proposal_rev = proposal.revision;
        revisions.push(proposal_rev);

        assert!(
            proposal_rev == prev_revision,
            "proposal revision should match current state"
        );

        let approval = Approval::for_proposal(&proposal);
        runtime.apply_change(proposal, approval).expect("apply");

        // After apply, revision should increment
        let next_authority = runtime.live_authority();
        prev_revision = next_authority.revision;
    }

    // Verify all proposals had correct revisions
    for (i, revision) in revisions.iter().enumerate() {
        assert_eq!(*revision, i as u64, "proposal {} had wrong revision", i);
    }

    // Verify all routes are still protected
    for i in 0..10 {
        let cap = runtime.get_route_protection(&Method::Post, &format!("/resource{}", i));
        assert_eq!(
            cap,
            Some(format!("resource{}.create", i)),
            "route {} should be protected",
            i
        );
    }
}

#[test]
fn protection_changes_are_immediately_visible() {
    let deployment = bootstrap(BindingMode::Embedded).expect("bootstrap deployment");
    let runtime = &deployment.runtime;

    // Scenario: rapidly toggle protection
    for _ in 0..5 {
        // Protect
        let protect = AuthorityChange::ProtectRoute {
            method: Method::Post,
            path: "/test".to_string(),
            capability: "test.write".to_string(),
        };
        let p1 = runtime.propose_change(protect).expect("propose");
        let a1 = Approval::for_proposal(&p1);
        runtime.apply_change(p1, a1).expect("apply");

        assert_eq!(
            runtime.get_route_protection(&Method::Post, "/test"),
            Some("test.write".to_string())
        );

        // Unprotect
        let unprotect = AuthorityChange::UnprotectRoute {
            method: Method::Post,
            path: "/test".to_string(),
        };
        let p2 = runtime.propose_change(unprotect).expect("propose");
        let a2 = Approval::for_proposal(&p2);
        runtime.apply_change(p2, a2).expect("apply");

        assert_eq!(runtime.get_route_protection(&Method::Post, "/test"), None);
    }
}
