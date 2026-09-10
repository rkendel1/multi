use std::collections::HashMap;

use appport_auth_mesh_contract::{AuditEventId, PrincipalId, TenantContext, TenantId};
use appport_auth_mesh_storage::memory::MemoryAuditLog;
use appport_auth_mesh_storage::{
    export_json_lines, AuditDurability, AuditEvent, AuditEventKind, AuditLog, StorageCapability,
    StorageTopology, StoreClass,
};

fn tenant(id: &str) -> TenantContext {
    TenantContext {
        tenant_id: TenantId(id.to_string()),
        namespace: id.to_string(),
        policy_id: format!("{}-policy", id).into(),
        storage_root_id: format!("{}-root", id).into(),
    }
}

fn event(id: &str, tenant: &TenantContext, timestamp: i64) -> AuditEvent {
    AuditEvent {
        event_id: AuditEventId(id.to_string()),
        tenant_id: tenant.tenant_id.clone(),
        principal_id: Some(PrincipalId("user:alice".to_string())),
        delegator_id: None,
        session_id: None,
        delegation_id: None,
        run_id: None,
        kind: AuditEventKind::AuthorizationDenied,
        timestamp,
        action: Some("invoice.update".to_string()),
        resource: Some("invoice:8472".to_string()),
        decision: Some("deny".to_string()),
        reason: Some("delegation_scope_denied".to_string()),
        authority_revision: Some(17),
        contract_fingerprint: Some("contract-1".to_string()),
        durability: AuditDurability::Required,
        metadata: HashMap::new(),
    }
}

#[test]
fn felt_db_and_postgres_reference_topologies_satisfy_authority_semantics() {
    for topology in [
        StorageTopology::authport_managed_feltdb(),
        StorageTopology::postgres_reference(),
    ] {
        for class in StoreClass::authority_classes() {
            let store = topology
                .stores
                .iter()
                .find(|store| store.class == class)
                .expect("authority store class is declared");
            assert!(store
                .capabilities
                .contains(&StorageCapability::DurableCommit));
            assert!(store
                .capabilities
                .contains(&StorageCapability::ConditionalWrite));
            assert!(store.capabilities.contains(&StorageCapability::Query));
        }

        let audit = topology
            .stores
            .iter()
            .find(|store| store.class == StoreClass::Audit)
            .expect("audit store is declared");
        assert!(audit.capabilities.contains(&StorageCapability::AppendOnly));
        assert!(audit
            .capabilities
            .contains(&StorageCapability::DurableCommit));
    }
}

#[test]
fn audit_store_is_append_ordered_tenant_scoped_and_exportable() {
    let tenant_a = tenant("acme");
    let tenant_b = tenant("globex");
    let audit = MemoryAuditLog::new();

    audit
        .record_event(&tenant_a, event("audit-1", &tenant_a, 10))
        .unwrap();
    audit
        .record_event(&tenant_a, event("audit-2", &tenant_a, 20))
        .unwrap();
    audit
        .record_event(&tenant_b, event("audit-3", &tenant_b, 15))
        .unwrap();

    let acme = AuditLog::events(&audit, &tenant_a, Some(11), 10).unwrap();
    assert_eq!(acme.len(), 1);
    assert_eq!(acme[0].event_id.as_str(), "audit-2");

    let exported = export_json_lines(&AuditLog::events(&audit, &tenant_a, None, 10).unwrap());
    assert!(exported.contains("\"id\":\"audit-1\""));
    assert!(exported.contains("\"decision\":\"deny\""));
    assert!(exported.contains("\"authority_revision\":17"));
    assert!(!exported.contains("audit-3"));
}
