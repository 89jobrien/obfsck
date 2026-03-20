//! Inspect the BAML schema IR for debugging

use obfsck::schema::analysis_ir;

fn main() {
    let ir = analysis_ir();

    println!("=== BAML Schema IR ===\n");
    println!("{:#?}", ir);

    println!("\n=== Schema Classes ===\n");
    for class in &ir.classes {
        println!("Class: {}", class.name);
        println!("  Fields:");
        for field in &class.fields {
            println!(
                "    - {}: {:?} (optional: {})",
                field.name, field.field_type, field.optional
            );
        }
        println!();
    }
}
