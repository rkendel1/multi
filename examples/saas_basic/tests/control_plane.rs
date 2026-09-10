use appport_auth_mesh_boundary::{
    Approval, AuthPortRuntime, AuthorityChange, Method, RegistrationPolicy,
};
use appport_auth_mesh_dsl::parse_auth_block;
use appport_auth_mesh_providers::ConnectorRegistry;
use appport_auth_mesh_runtime::MemoryStores;

const DECLARATION: &str = r#"
use auth {
  providers = [local]
  tenant = true
  claims = {
    role = enum["owner", "member"]
  }
}
"#;

fn setup() -> AuthPortRuntime {
    let config = parse_auth_block(DECLARATION).expect("parse declaration");
    let registry = ConnectorRegistry::from_config(&config).expect("registry");
    let stores = MemoryStores::new();

    let runtime = AuthPortRuntime::standalone(config, registry, stores.mesh_stores())
        .expect("create runtime")
        .with_registration(RegistrationPolicy::self_service(&[("role", "member")]));

    runtime
}

#[test]
fn control_plane_proposes_and_applies_protection() {
    let runtime = setup();

    // 1. Initially no protection
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        None,
        "POST /invoices should start unprotected"
    );

    // 2. Propose: Protect POST /invoices with capability "invoice.create"
    let change = AuthorityChange::ProtectRoute {
        method: Method::Post,
        path: "/invoices".to_string(),
        capability: "invoice.create".to_string(),
    };

    let proposal = runtime.propose_change(change).expect("propose change");

    // Verify the preview shows before/after difference
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
                    && p.capability
                        .as_ref()
                        .map_or(false, |c| c == "invoice.create")
            }),
        "after: POST /invoices should require invoice.create"
    );

    // 3. Apply the proposal with approval
    let approval = Approval::for_proposal(&proposal);
    let change_id = runtime
        .apply_change(proposal, approval)
        .expect("apply change");
    assert!(!change_id.is_empty(), "should return a change ID");

    // 4. Verify the protection is now active
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        Some("invoice.create".to_string()),
        "POST /invoices should now require invoice.create"
    );

    println!("✓ Proposal and apply test passed!");
}

#[test]
fn control_plane_approval_token_mismatch() {
    let runtime = setup();

    let change = AuthorityChange::ProtectRoute {
        method: Method::Post,
        path: "/test".to_string(),
        capability: "test.write".to_string(),
    };

    let proposal = runtime.propose_change(change).expect("propose change");

    // Create an approval for a different proposal
    let different_change = AuthorityChange::ProtectRoute {
        method: Method::Put,
        path: "/other".to_string(),
        capability: "other.write".to_string(),
    };
    let different_proposal = runtime
        .propose_change(different_change)
        .expect("propose change");
    let wrong_approval = Approval::for_proposal(&different_proposal);

    // Try to apply with wrong approval
    let result = runtime.apply_change(proposal, wrong_approval);
    assert!(result.is_err(), "should fail with mismatched approval");
    assert!(
        result.unwrap_err().contains("does not match"),
        "error should explain the mismatch"
    );
}

#[test]
fn control_plane_revision_conflict() {
    let runtime = setup();

    let change1 = AuthorityChange::ProtectRoute {
        method: Method::Post,
        path: "/a".to_string(),
        capability: "a.create".to_string(),
    };

    let change2 = AuthorityChange::ProtectRoute {
        method: Method::Put,
        path: "/b".to_string(),
        capability: "b.update".to_string(),
    };

    // Get both proposals at revision 0
    let proposal1 = runtime.propose_change(change1).expect("propose 1");
    let proposal2 = runtime.propose_change(change2).expect("propose 2");

    assert_eq!(proposal1.revision, 0);
    assert_eq!(proposal2.revision, 0);

    // Apply first one (should succeed, revision advances to 1)
    let approval1 = Approval::for_proposal(&proposal1);
    let _id1 = runtime.apply_change(proposal1, approval1).expect("apply 1");

    // Try to apply second one (should fail, it's based on old revision 0)
    let approval2 = Approval::for_proposal(&proposal2);
    let result = runtime.apply_change(proposal2, approval2);

    assert!(result.is_err(), "applying stale proposal should fail");
    assert!(
        result.unwrap_err().contains("conflicts"),
        "error should mention conflict"
    );
}

#[test]
fn control_plane_route_protection_query() {
    let runtime = setup();

    // Initially no protection
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        None
    );

    // Protect the route
    let change = AuthorityChange::ProtectRoute {
        method: Method::Post,
        path: "/invoices".to_string(),
        capability: "invoice.create".to_string(),
    };

    let proposal = runtime.propose_change(change).expect("propose");
    let approval = Approval::for_proposal(&proposal);
    runtime.apply_change(proposal, approval).expect("apply");

    // Now protection is set
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        Some("invoice.create".to_string())
    );

    // Different method/path should not be protected
    assert_eq!(
        runtime.get_route_protection(&Method::Get, "/invoices"),
        None
    );
    assert_eq!(runtime.get_route_protection(&Method::Post, "/orders"), None);
}

#[test]
fn control_plane_unprotect_route() {
    let runtime = setup();

    // Protect
    let protect = AuthorityChange::ProtectRoute {
        method: Method::Post,
        path: "/sensitive".to_string(),
        capability: "sensitive.write".to_string(),
    };

    let p1 = runtime.propose_change(protect).expect("propose protect");
    let a1 = Approval::for_proposal(&p1);
    runtime.apply_change(p1, a1).expect("apply protect");

    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/sensitive"),
        Some("sensitive.write".to_string())
    );

    // Unprotect
    let unprotect = AuthorityChange::UnprotectRoute {
        method: Method::Post,
        path: "/sensitive".to_string(),
    };

    let p2 = runtime
        .propose_change(unprotect)
        .expect("propose unprotect");
    let a2 = Approval::for_proposal(&p2);
    runtime.apply_change(p2, a2).expect("apply unprotect");

    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/sensitive"),
        None
    );
}

#[test]
fn control_plane_provider_enable_disable() {
    let runtime = setup();

    // By default, local provider should be enabled
    assert!(
        runtime.is_provider_enabled("local"),
        "local provider should default to enabled"
    );

    // Disable it
    let disable = AuthorityChange::SetProviderEnabled {
        provider: "local".to_string(),
        enabled: false,
    };

    let p1 = runtime.propose_change(disable).expect("propose disable");
    let a1 = Approval::for_proposal(&p1);
    runtime.apply_change(p1, a1).expect("apply disable");

    assert!(
        !runtime.is_provider_enabled("local"),
        "local provider should be disabled"
    );

    // Re-enable it
    let enable = AuthorityChange::SetProviderEnabled {
        provider: "local".to_string(),
        enabled: true,
    };

    let p2 = runtime.propose_change(enable).expect("propose enable");
    let a2 = Approval::for_proposal(&p2);
    runtime.apply_change(p2, a2).expect("apply enable");

    assert!(
        runtime.is_provider_enabled("local"),
        "local provider should be enabled again"
    );
}

#[test]
fn control_plane_persists_proposals_history_and_reverts() {
    let runtime = setup();

    let proposal = runtime
        .propose_change(AuthorityChange::ProtectRoute {
            method: Method::Post,
            path: "/invoices".to_string(),
            capability: "invoice.create".to_string(),
        })
        .expect("propose protection");
    let proposal_id = proposal.id.clone();

    let stored = runtime
        .retrieve_proposal(&proposal_id)
        .expect("proposal is stored");
    assert_eq!(stored.id, proposal_id);
    assert_eq!(stored.revision, 0);
    assert_eq!(runtime.list_proposals(10, 0).unwrap().len(), 1);

    let approval = Approval::for_proposal(&proposal);
    let change_id = runtime.apply_change(proposal, approval).expect("apply");

    assert_eq!(runtime.live_authority().revision, 1);
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        Some("invoice.create".to_string())
    );

    let history = runtime.history(10, 0).expect("history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].change_id, change_id);
    assert_eq!(history[0].previous_state.revision, 0);
    assert_eq!(history[0].resulting_state.revision, 1);

    let revert = runtime
        .propose_change(AuthorityChange::Revert {
            change_id: change_id.clone(),
        })
        .expect("propose revert");
    assert_eq!(revert.revision, 1);
    let approval = Approval::for_proposal(&revert);
    let revert_id = runtime
        .apply_change(revert, approval)
        .expect("apply revert");

    assert_ne!(revert_id, change_id);
    assert_eq!(runtime.live_authority().revision, 2);
    assert_eq!(
        runtime.get_route_protection(&Method::Post, "/invoices"),
        None
    );

    let history = runtime.history(10, 0).expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].reverted_change_id, Some(change_id));
}
