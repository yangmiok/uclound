#!/bin/sh

# REAME
# make bench
# nohup ./bench.sh &
# tail -f nohup.out
# REAME end

#size=34359738368 # 32GB
size=536870912 # 512MB
#size=2048 # 2KB

export IPFS_GATEWAY="https://proof-parameters.s3.cn-south-1.jdcloud-oss.com/ipfs/"

# Note that FIL_PROOFS_USE_GPU_TREE_BUILDER=1 is for tree_r_last building and FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1 is for tree_c.  
# So be sure to use both if you want both built on the GPU
export FIL_PROOFS_USE_GPU_COLUMN_BUILDER=0
export FIL_PROOFS_USE_GPU_TREE_BUILDER=0 
export FIL_PROOFS_MAXIMIZE_CACHING=1  # open cache for 32GB or 64GB
export FIL_PROOFS_USE_MULTICORE_SDR=1
export BELLMAN_NO_GPU=1

# checking gpu
gpu=""
type nvidia-smi
if [ $? -eq 0 ]; then
    gpu=$(nvidia-smi -L|grep "GPU")
fi
if [ ! -z "$gpu" ]; then
    FIL_PROOFS_USE_GPU_COLUMN_BUILDER=1
    FIL_PROOFS_USE_GPU_TREE_BUILDER=1
    BELLMAN_NO_GPU=0
fi


# offical bench
RUST_LOG=info RUST_BACKTRACE=1 ./lotus-bench sealing --storage-dir=/data/cache/.lotus-bench --sector-size=$size &

# fivestar bench
#################
# --max-tasks 需要运行的任务数，需要注意硬盘空间是否足够
# --taskset   是否使用golang进程进行cpu锁核，true为启用，会在p1与p2启用独立的进程进行锁核计算; false会直接使用rust原生计算 
# --parallel-addpiece addpiece可同时并行的数量, 若值为0，在上一阶段结束后结束测试
# --parallel-precommit1 precommit1可同时并行的数量, 若值为0，在上一阶段结束后结束测试
# --parallel-precommit2 precommit2可同时并行的数量, 若值为0，在上一阶段结束后结束测试
# --parallel-commit1 commit1可同时并行的数量, 若值为0，在上一阶段结束后结束测试
# --parallel-commit2 commit2可同时并行的数量, 若值为0，在上一阶段结束后结束测试
#################
#
#RUST_LOG=info RUST_BACKTRACE=1 ./lotus-bench p-run --storage-dir=/data/cache/.lotus-bench --sector-size=$size \
#    --max-tasks=2 \
#    --taskset=false \ 
#    --parallel-addpiece=2 \
#    --parallel-precommit1=2 \
#    --parallel-precommit2=1 \
#    --parallel-commit1=1 \
#    --parallel-commit2=1 &

pid=$!


# set ulimit for process
nropen=$(cat /proc/sys/fs/nr_open)
echo "max nofile limit:"$nropen
echo "current nofile of $pid limit:"$(cat /proc/$pid/limits|grep "open files")
prlimit -p $pid --nofile=$nropen
if [ $? -eq 0 ]; then
    echo "new nofile of $pid limit:"$(cat /proc/$pid/limits|grep "open files")
else
    echo "set prlimit failed, command:prlimit -p $pid --nofile=$nropen"
    exit 0
fi

wait $pid

