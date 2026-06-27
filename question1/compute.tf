# Compute Engine instance that will live in the PRIVATE subnet
resource "google_compute_instance" "backend_vm" {
  # Name of the VM in GCP
  name         = "backend-vm"
  machine_type = "e2-micro"

  # Zone must be in the same region as your subnet (example: us-central1-a)
  zone = "${var.region}-a"

  # Basic boot disk using a Debian image
  boot_disk {
    initialize_params {
      image = "projects/debian-cloud/global/images/family/debian-12"
    }
  }

  # Network interface: attach to the PRIVATE subnet, NO external IP
  network_interface {
    subnetwork = google_compute_subnetwork.private_subnet.id

    # Omitting access_config means
  }

  # Tags used later by firewall rules (SSH, HTTP from LB, etc.)
  tags = ["backend", "ssh-admin", "web-backend"]
}
