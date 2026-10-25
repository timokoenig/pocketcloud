//! First boot of the server: admin user with the ssh key, bootstrap firewall. Everything else (hardening,
//! packages, docker, caddy, the daemon) is installed by assets/install.sh over ssh, and again on every upgrade.

pub struct CloudInit<'a> {
    pub hostname: &'a str,
    pub ssh_user: &'a str,
    pub ssh_public_key: &'a str,
}

pub fn render(c: &CloudInit) -> String {
    let template = include_str!("../assets/cloud-init.yaml");
    template
        .replace("${HOSTNAME}", c.hostname)
        .replace("${SSH_USER}", c.ssh_user)
        .replace("${SSH_PUB}", c.ssh_public_key.trim())
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders() {
        let s = super::render(&super::CloudInit { hostname: "pc", ssh_user: "admin", ssh_public_key: "ssh-ed25519 AAA x" });
        assert!(s.starts_with("#cloud-config"));
        assert!(!s.contains("${"));
        assert!(s.contains("name: admin"));
        assert!(s.contains("policy drop"));
    }
}
