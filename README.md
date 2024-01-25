# tfe-fdo-docker
This repository will install TFE FDO on Docker in External Services configuration on AWS infrastructure with Postgres 14.9 version.

Here is the [Terraform Enterprise official documentation](https://developer.hashicorp.com/terraform/enterprise/flexible-deployments/install/docker/install)


## Pre-requisites

- [X] [Terraform Enterprise License](https://www.hashicorp.com/products/terraform/pricing)
- [X] [AWS Account](https://aws.amazon.com/free/?gclid=Cj0KCQiAy9msBhD0ARIsANbk0A9djPCZfMAnJJ22goFzJssB-b1RfMDf9XvUYa0NuQ8old01xs4u8wIaAts9EALw_wcB&trk=65c60aef-03ac-4364-958d-38c6ccb6a7f7&sc_channel=ps&ef_id=Cj0KCQiAy9msBhD0ARIsANbk0A9djPCZfMAnJJ22goFzJssB-b1RfMDf9XvUYa0NuQ8old01xs4u8wIaAts9EALw_wcB:G:s&s_kwcid=AL!4422!3!458573551357!e!!g!!aws%20account!10908848282!107577274535&all-free-tier.sort-by=item.additionalFields.SortRank&all-free-tier.sort-order=asc&awsf.Free%20Tier%20Types=*all&awsf.Free%20Tier%20Categories=*all)
- [X] [Terraform](https://www.terraform.io/downloads)


# Steps on how to use this repository

- Clone this repository:
```shell
git clone git@github.com:dlavric/tfe-fdo-docker.git
```

- Go to the directory where the repository is stored:
```shell
cd tfe-fdo-docker
```

- Attach your TFE FDO License that you have purchased to the repository root folder

- Create a file `variables.auto.tfvars` with the following content
```hcl
aws_region       = "eu-west-2"
tfe_version      = "v202312-1"
tfe_hostname     = "daniela-docker1.tf-support.hashicorpdemo.com"
tfe_subdomain    = "daniela-docker1"
tfe_domain       = "tf-support.hashicorpdemo.com"
email            = "daniela@hashicorp.com"
username         = "dlavric"
password         = "DanielaLavric"
certs_bucket     = "daniela-fdo-certs1"
license_bucket   = "daniela-fdo-license1"
storage_bucket   = "daniela-fdo-storage"
license_filename = "fdo-license.txt"
key_pair         = "daniela-fdo-key2"
enc_password     = "encpassword"
db_identifier    = "daniela-db-docker"
db_name          = "danieladb"
db_username      = "postgres"
db_password      = "dbpassword"
```

- Export AWS environment variables
```shell
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_SESSION_TOKEN=
export AWS_REGION= 
```

- Download all the Terraform dependencies for modules and providers
```shell
terraform init
```

- Verify the output is successfull
```shell
Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/tls from the dependency lock file
- Reusing previous version of hashicorp/aws from the dependency lock file
- Reusing previous version of vancluever/acme from the dependency lock file
- Using previously-installed hashicorp/tls v4.0.5
- Using previously-installed hashicorp/aws v5.26.0
- Using previously-installed vancluever/acme v2.17.2

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

- Apply all the changes
```shell
terraform apply
```

- Verify the output matches in number of resources
```shell
Plan: 26 to add, 0 to change, 0 to destroy.
```

- Wait a couple of minutes for TFE to become online

- Access the TFE environment at the following URL: https://daniela-docker1.tf-support.hashicorpdemo.com

- Destroy you infrastructure
```shell
terraform destroy
```

- Verify the output matches in number of resources
```shell

```




What do I need:

- [X] AWS Instance that has 4 CPU and 16GB minimum as per [official requirements](https://developer.hashicorp.com/terraform/enterprise/replicated/architecture/reference-architecture/aws#terraform-enterprise-server-ec2-via-auto-scaling-group)
- [X] DNS hostname for the server
- [X] Valid certificates created with Let's encrypt, [see this Github repo](https://github.com/dlavric/create-certificates) that will be incorporated here
- [X] Automate the installation of Docker on the EC2 instance
- [X] Automate the adding of the certificates to the `/certs` folder
- [X] Automate pulling the Docker container and install TFE with the `compose.yaml` file
- [X] Add your license file to the repository folder and ignore it in the gitignore file
- [X] Add more dynamic variables for easier maintenance of the repository
- [X] Add an output for the IP of my instance 
- [X] Add an output for the URL of my instance
- [X] Create TFE initial user
- [X] External Services: Postgres & S3 bucket
- [X] Create the Postgres DB in the same VPC/subnet as the EC2 instance
- [X] Allow traffic to and from port 5432 in the security group for the PostgresSQL DB
- [X] Modify the YAML Template to have an External Services configuration
- [ ] Create Redis
- [ ] Create Load balancer
- [ ] Create AWS Launch template
- [ ] Create Auto Scaling Group
- [ ] Create yaml template for Active/Active configuration
- [ ] Create new variables for Redis
- [ ] Open ports for Redis and Vault in the security group
