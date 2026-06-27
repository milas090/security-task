# Allow SSH (22) only from a trusted CIDR to the backend VM
resource "google_compute_firewall" "allow_ssh_trusted" {
  name    = "allow-ssh-trusted"
  network = google_compute_network.main_vpc.name

  direction = "INGRESS"
  priority  = 1000

  # Only TCP/22 (SSH)
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Only from your trusted IP range (e.g., 203.0.113.10/32), not from the whole internet
  source_ranges = [var.trusted_ssh_cidr]

  # Apply this rule only to instances with this network tag
  target_tags = ["ssh-admin"]
}

# Allow HTTP (80) only from Google HTTP(S) LB IP ranges to backend VM
resource "google_compute_firewall" "allow_http_from_lb" {
  name    = "allow-http-from-lb"
  network = google_compute_network.main_vpc.name

  direction = "INGRESS"
  priority  = 1000

  allow {
    protocol = "tcp"
    ports    = ["80"]
  }

  # IP ranges used by Google HTTP(S) Load Balancer and health checks
  source_ranges = [
    "35.191.0.0/16",
    "130.211.0.0/22",
  ]

  # Apply to instances that act as web backends
  target_tags = ["web-backend"]
}
