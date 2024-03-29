output "public_ip" {
  value = aws_eip.eip.public_ip #this should be the public ip of the jump host , the aws instance
}

output "url" {
  value = "https://${var.tfe_hostname}"
}

output "ssh_connect" {
  value = "ssh -i ${var.key_pair}.pem ubuntu@${aws_eip.eip.public_ip}"
  #ssh -J ubuntu@jumphost_public_ip ubuntu@private_ip_tfe_instance
}

#create the key.pem file on the asg instance
#chmod 600 daniela-key.pem
#ssh -i daniela-fdo-key2.pem ubuntu@private_ip