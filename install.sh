#!/bin/bash

# Bash Installation Script for UNIX Systems only

os="$(uname -s)_$(uname -m)"

if [ $os == "Linux_amd64" ] || [ $os == "Linux_386" ]; then
        echo "Installing GoScan..."
        goscan_version=$(curl -s https://api.github.com/repos/marco-lancini/goscan/releases/latest | grep tag_name | cut -d '"' -f 4)
        echo "Downloading version $goscan_version"
        wget https://github.com/marco-lancini/goscan/releases/download/$goscan_version/goscan_$goscan_version_$os.zip
        unzip goscan_$goscan_version_$os.zip
        rm goscan_$goscan_version_$os.zip
        echo "Installation completed Successfully."
        echo "To install it globally:"
        echo "chmod +x goscan"
        echo "sudo mv ./goscan /usr/local/bin/goscan"
else
        echo "Your Distro is not Supported."
        exit 1
fi

exit 0
