cd samples/bpf
make

for f in ndp_*.o
do
    objcopy -O binary -I elf32-little --only-section=nvme_ndpm "$f" ../../ndpm_modules/"${f%.*}".ebpf
done

cd ../..

