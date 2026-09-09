use appport_auth_mesh_dsl::parse_auth_block;

fn main() {
    let src = include_str!("../appport.toml");
    let config = parse_auth_block(src).expect("example config should parse");
    println!("auth providers: {:?}", config.providers);
}
