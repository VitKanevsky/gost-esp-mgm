# README #

Linux kernel module that implements the GOST 34.12-2015 encryption algorithm, 
MGM mode (RFC 9227), for working as part of the IPSEC Linux esp protocol

Kernel Crypto modules implementation of russian GOST cryptography for ipsec esp.
dkms support for update kernel modules 

## Instalation ##



### For make deb package ###

sudo apt-get install dpkg debconf debhelper lintian 

cd gost-esp-mgm
fakeroot dpkg-deb -b kuznyechik_crypto_mgm-1.0.0/ kuznyechik_crypto_mgm_1.0.0_amd64.deb

### For install builded deb package ###
sudo dpkg -i kuznyechik_crypto_mgm_1.0.0_amd64.deb

this will install the following modules 

kuznyechik_mgm_esp.ko
xfrm_algo.ko

modules will be added to /etc/modules for autoload at start 

dkms will be configured for rebuild these modules at upgrade linux kernel. 

### Check 

lsmod | grep kuznyechik

cat /proc/crypto | grep kuznyechik

### testing module
cd test_kuznyechik_mgm
make 
sudo insmod ./test_kuznyechik_mgm.ko
sudo rmmod test_kuznyechik_mgm
