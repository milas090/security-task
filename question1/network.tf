# Create a custom VPC network (no automatic subnets)
resource "google_compute_network" "main_vpc" {
  # Name of the VPC as it will appear in GCP
  name = "main-vpc"

  # Disable auto subnet creation so we define ALL subnets explicitly
  auto_create_subnetworks = false
}

# Public subnet in the VPC (will later be used for LB-related resources)
resource "google_compute_subnetwork" "public_subnet" {
  # Name of the subnet in GCP
  name = "public-subnet"

  # CIDR block for this subnet (no overlap with private subnet)
  ip_cidr_range = "10.0.0.0/24"

  # Region where this subnet exists (comes from var.region)
  region = var.region

  # Attach this subnet to the main_vpc we created above
  network = google_compute_network.main_vpc.id
}

# Private subnet in the VPC (for the backend VM)
resource "google_compute_subnetwork" "private_subnet" {
  # Name of the subnet in GCP
  name = "private-subnet"

  # Separate CIDR block for private resources
  ip_cidr_range = "10.0.1.0/24"

  # Same region as the public subnet (can be changed if needed)
  region = var.region

  # Attach this subnet to the same main VPC
  network = google_compute_network.main_vpc.id
}
