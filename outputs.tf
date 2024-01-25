output "public_ip" {
  value = aws_eip.eip.public_ip
}

output "url" {
  value = "https://${var.tfe_hostname}"
}

output "ssh_connect" {
  value = "ssh -i ${var.key_pair}.pem ubuntu@${aws_eip.eip.public_ip}"
}