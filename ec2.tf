
####################################################################################
#####################    AWS prvider details        ################################
####################################################################################

provider "aws" {
  region = "ap-south-1"
  profile = "hita"
}


####################################################################################
###################    Create Security Group        ################################
####################################################################################

resource "aws_security_group" "http_ssh_protocol" {
  name        = "allow_http_ssh"
  description = "Allow http and ssh inbound traffic"
  vpc_id      = "vpc-91ecf1f9"


  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "ssh from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp" 
    cidr_blocks = ["0.0.0.0/0"]
  }


  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_http_ssh"
  }
}


####################################################################################
##################    Create Key Pair and Save       ###############################
####################################################################################

resource "tls_private_key" "key_ssh" {
  depends_on = [aws_security_group.http_ssh_protocol,


  ]
   algorithm  = "RSA"
  rsa_bits   = 4096
}
resource "aws_key_pair" "key2" {
  key_name   = "key2"
  public_key = tls_private_key.key_ssh.public_key_openssh
}
output "key_ssh" {
  value = tls_private_key.key_ssh.private_key_pem
}
resource "local_file" "save_key" {
    content     = tls_private_key.key_ssh.private_key_pem
    filename = "key2.pem"
}


####################################################################################
############# create Ec2 instance   ################################################
####################################################################################

resource "aws_instance" "web" {
  depends_on = [aws_key_pair.key2,tls_private_key.key_ssh,local_file.save_key]
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  key_name = "key2"
  security_groups = [ "allow_http_ssh" ]

  tags = {
    Name = "myweb1"
  }

}


##############################################################################################
########################## create ebs volume   ###############################################
##############################################################################################

resource "aws_ebs_volume" "ebs1" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1
  tags = {
    Name = "myebs"
  }
}




######################################################################################################
############   saving the public ip   ###############################################################
######################################################################################################

resource "null_resource" "nulllocal2"  {
        provisioner "local-exec" {
            command = "echo  ${aws_instance.web.public_ip} > publicip.txt"
        }
}

######################################################################################################
#######connect to ec-2 and fromat mount git clone
######################################################################################################

resource "null_resource" "nullremote3"  {

depends_on = [aws_ebs_volume.ebs1]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.key_ssh.private_key_pem
    host     = aws_instance.web.public_ip
  }

provisioner "remote-exec" {
    inline = [
	  "sudo yum install httpd -y",
      "sudo yum install git -y",
      "sudo systemctl restart httpd",
      "sudo systemctl enable httpd",
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/hitebrata/hybridcc_task1.git /var/www/html/"
    ]
  }
}



resource "null_resource" "nulllocal1"  {


depends_on = [
    null_resource.nullremote3,
  ]

        provisioner "local-exec" {
            command = "start chrome  ${aws_instance.web.public_ip}"
        }
}


##########################################################################################################################
##Create S3 bucket and deploy the images from github repo into the s3 bucket and change the permission to public readable.
##########################################################################################################################

resource "null_resource" "null2"  {
  provisioner "local-exec" {
      command = "git clone https://github.com/hitebrata/hybridcc_task1.git ./gitcode"
    }
}    

resource "aws_s3_bucket" "bucket36" {
  bucket = "bucket36"
  acl    = "public-read"
  versioning {
  enabled = true
}

  tags = {
    Name        = "bucket36"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_object" "obj1" {
  key = "DevOps_lifecycle.jpg"
  bucket = "aws_s3_bucket.bucket36.id"
  source = "./gitcode/DevOps_lifecycle.jpg"
  acl = "public-read"
}


###########################################################################################################################
##Create a Cloudfront using s3 bucket which contains images and use the Cloudfront URL to update in code in /var/www/html##
###########################################################################################################################

resource "aws_cloudfront_distribution" "cloudfront1" {
    origin {
        domain_name = "mycode.s3.amazonaws.com"
        origin_id = "${aws_s3_bucket.bucket36.id}"



        custom_origin_config {
            http_port = 80
            https_port = 80
            origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        }
    }


    enabled = true

    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = aws_s3_bucket.bucket36.id


        forwarded_values {
            query_string = false


            cookies {
               forward = "none"
            }
        }
        viewer_protocol_policy = "allow-all"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }


    restrictions {
        geo_restriction {


            restriction_type = "none"
        }
    }


    viewer_certificate {
        cloudfront_default_certificate = true
    }
}





