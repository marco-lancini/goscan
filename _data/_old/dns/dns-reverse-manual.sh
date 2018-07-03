
DNS="192.168.13.221"

for IP in {200..255}
do
	name=$(host 192.168.13.$IP $DNS | grep name | cut -d " " -f 5)
	echo $IP " - " $name
done
