cd samples/bpf
make

for f in ndp_*.o
do
    objcopy -O binary -I elf64-little --only-section=.text "$f" ../../ndpm_modules/"${f%.*}".ebpf
done

cd ../..

