use serde::{Deserialize, Serialize};
use simplify_baml::BamlSchemaRegistry;

#[derive(Debug, Clone, Serialize, Deserialize, simplify_baml::DeriveBamlSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisOutput {
    pub attack_vector: String,
    pub mitre_attack: MitreAttack,
    pub risk: Risk,
    pub investigate: Vec<String>,
    pub mitigations: Mitigations,
    pub false_positive: FalsePositive,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, simplify_baml::DeriveBamlSchema)]
#[serde(deny_unknown_fields)]
pub struct MitreAttack {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
    pub sub_technique: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, simplify_baml::DeriveBamlSchema)]
#[serde(deny_unknown_fields)]
pub struct Risk {
    pub severity: String,
    pub confidence: String,
    pub impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, simplify_baml::DeriveBamlSchema)]
#[serde(deny_unknown_fields)]
pub struct Mitigations {
    pub immediate: Vec<String>,
    pub short_term: Vec<String>,
    pub long_term: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, simplify_baml::DeriveBamlSchema)]
#[serde(deny_unknown_fields)]
pub struct FalsePositive {
    pub likelihood: String,
    pub common_causes: Vec<String>,
    pub distinguishing_factors: Vec<String>,
}

pub fn analysis_ir() -> simplify_baml::IR {
    BamlSchemaRegistry::new()
        .register::<AnalysisOutput>()
        .build()
}
