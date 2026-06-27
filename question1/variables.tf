variable "project_id" {
  type        = string
  description = "GCP project ID" //project-b60fa3d7-df50-46ed-982
}

variable "region" {
  type        = string
  description = "Default GCP region"
  default     = "us-central1"
}

variable "trusted_ssh_cidr" {
  type        = string
  description = "CIDR allowed to SSH into backend VM (e.g. your_ip/32)" //as security best practice only your ip or range can access
}
