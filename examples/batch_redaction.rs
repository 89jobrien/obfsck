use obfsck::{obfuscate_text, ObfuscationLevel};

fn main() {
    let mut records = Vec::new();

    for i in 0..250 {
        records.push(format!(
            "event_id=evt-{i:04} user=user{} src=10.1.{}.{} dst=198.51.100.{} email=user{}@corp.example host=service{}.corp.example path=/var/lib/app{}/env{}.json",
            i % 40,
            (i % 30) + 1,
            (i % 250) + 1,
            (i % 200) + 10,
            i % 40,
            i % 12,
            i % 8,
            i
        ));
    }

    let mut total_in = 0usize;
    let mut total_out = 0usize;
    let mut max_ip_tokens = 0usize;
    let mut max_user_tokens = 0usize;
    let mut max_email_tokens = 0usize;

    for record in &records {
        let (out, map) = obfuscate_text(record, ObfuscationLevel::Paranoid);
        total_in += record.len();
        total_out += out.len();
        max_ip_tokens = max_ip_tokens.max(map.ips.len());
        max_user_tokens = max_user_tokens.max(map.users.len());
        max_email_tokens = max_email_tokens.max(map.emails.len());
    }

    println!("Processed {} records", records.len());
    println!("Input bytes: {total_in}");
    println!("Output bytes: {total_out}");
    println!("Max tokens in a single record:");
    println!("  ips={max_ip_tokens} users={max_user_tokens} emails={max_email_tokens}");
    println!("Sample before: {}", records[0]);
    let (sample_out, _) = obfuscate_text(&records[0], ObfuscationLevel::Paranoid);
    println!("Sample after : {sample_out}");
}
