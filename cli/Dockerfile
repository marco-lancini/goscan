FROM golang:1.10-stretch AS build

# Update
RUN apt-get update && apt-get install -y zip libc6-dev-i386 nmap

# Setup workdir
WORKDIR /go/src/github.com/marco-lancini/goscan

# Setup project
#COPY goscan/ /go/src/github.com/marco-lancini/goscan
#RUN CGO_ENABLED=0 go build -o /bin/goscan

#FROM scratch
#COPY --from=build /bin/goscan /bin/goscan
#ENTRYPOINT ["/bin/goscan"]
