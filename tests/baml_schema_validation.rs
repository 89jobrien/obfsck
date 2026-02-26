use obfsck::schema::{analysis_ir, AnalysisOutput};
use simplify_baml::{parse_llm_response_with_ir, BamlSchema, FieldType};

#[test]
fn test_baml_schema_parses_valid_response() {
    let sample = include_str!("fixtures/sample_llm_response.json");
    let ir = analysis_ir();
    let output_type = FieldType::Class(AnalysisOutput::schema_name().to_string());

    let result = parse_llm_response_with_ir(&ir, sample, &output_type);
    assert!(
        result.is_ok(),
        "Failed to parse valid LLM response: {:?}",
        result.err()
    );

    let parsed = result.unwrap();
    let typed: Result<AnalysisOutput, _> = serde_json::from_value(serde_json::to_value(parsed).unwrap());
    assert!(typed.is_ok(), "Failed to deserialize to AnalysisOutput");

    let analysis = typed.unwrap();
    assert_eq!(analysis.mitre_attack.tactic, "Initial Access");
    assert_eq!(analysis.mitre_attack.technique_id, "T1078");
    assert_eq!(analysis.risk.severity, "High");
    assert!(!analysis.investigate.is_empty());
    assert!(!analysis.mitigations.immediate.is_empty());
}

#[test]
fn test_baml_schema_rejects_invalid_response() {
    let invalid_json = r#"{"invalid": "structure"}"#;
    let ir = analysis_ir();
    let output_type = FieldType::Class(AnalysisOutput::schema_name().to_string());

    let result = parse_llm_response_with_ir(&ir, invalid_json, &output_type);
    assert!(
        result.is_err(),
        "Should reject invalid LLM response structure"
    );
}

#[test]
fn test_baml_schema_handles_missing_fields() {
    let incomplete = r#"{
        "attack_vector": "Test",
        "mitre_attack": {
            "tactic": "Test",
            "technique_id": "T1234",
            "technique_name": "Test"
        },
        "risk": {
            "severity": "Low",
            "confidence": "High",
            "impact": "None"
        }
    }"#;

    let ir = analysis_ir();
    let output_type = FieldType::Class(AnalysisOutput::schema_name().to_string());

    let result = parse_llm_response_with_ir(&ir, incomplete, &output_type);
    assert!(
        result.is_err(),
        "Should reject response with missing required fields"
    );
}

#[test]
fn test_baml_schema_ignores_extra_fields() {
    let sample = include_str!("fixtures/sample_llm_response.json");
    let with_extra = sample.trim_end_matches('}').to_string() + r#", "extra_field": "should_be_ignored"}"#;

    let ir = analysis_ir();
    let output_type = FieldType::Class(AnalysisOutput::schema_name().to_string());

    let result = parse_llm_response_with_ir(&ir, &with_extra, &output_type);
    // BAML parser is lenient with extra fields - it only extracts known fields
    // This is actually desirable for LLM responses which may include extra commentary
    assert!(
        result.is_ok(),
        "BAML parser should gracefully ignore extra fields: {:?}",
        result.err()
    );

    let parsed = result.unwrap();
    let typed: Result<AnalysisOutput, _> = serde_json::from_value(serde_json::to_value(parsed).unwrap());
    assert!(typed.is_ok(), "Should deserialize successfully, ignoring extra fields");
}
