#
# Commands for building the container and accessing it.
# Instead of a README, we just have them here in a self-explained makefile.
#

build_container:
	docker buildx build --platform=linux/amd64 -t my_ubuntu .

run_container:
	docker run -dit --platform=linux/amd64 --detach-keys="ctrl-]" --name ubuntu_vm my_ubuntu


set_automatic_restarts_after_reboot:
	docker run -dit --platform=linux/amd64 --restart unless-stopped --name ubuntu_vm my_ubuntu

access:
	docker exec -it ubuntu_vm bash

stop:
	docker stop ubuntu_vm

start:
	docker start ubuntu_vm

remove:
	docker rm -f ubuntu_vm

show_running_containerws:
	docker ps

show_all_containers:
	docker ps -a
