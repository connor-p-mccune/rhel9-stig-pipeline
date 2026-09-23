# =============================================================================
# terraform/server/outputs.tf
#
# Outputs are the values Terraform prints after an apply, and that you can read
# back at any time with `terraform output`. They save you from hunting through
# the AWS console for an IP address or an instance ID.
# =============================================================================

output "public_ip" {
  description = "Public IP address of the test server. NOTE: this changes every time the server is stopped and started again."
  value       = aws_instance.stig_target.public_ip
}

output "instance_id" {
  description = "AWS instance ID (i-...). Use this with aws ec2 stop-instances / start-instances."
  value       = aws_instance.stig_target.id
}

output "ami_id" {
  description = "The Red Hat RHEL 9 image ID this server was launched from. Record it in docs/decisions.md - the numbers in this project are only reproducible against a known starting image."
  value       = data.aws_ami.rhel9.id
}

output "ami_name" {
  description = "Human-readable name of that image, e.g. RHEL-9.4.0_HVM-...  Easier to write in docs than the raw ID."
  value       = data.aws_ami.rhel9.name
}

output "ssh_command" {
  description = "Ready-to-paste SSH command for this server."
  value       = "ssh -i ~/.ssh/stig-lab ec2-user@${aws_instance.stig_target.public_ip}"
}

output "allowed_ssh_cidr" {
  description = "The one address allowed to reach port 22. If your home IP changes, this is what needs updating - run terraform apply again."
  value       = "${chomp(data.http.myip.response_body)}/32"
}
