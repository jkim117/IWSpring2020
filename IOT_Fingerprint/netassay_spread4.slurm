#!/bin/bash
## Double hash sign (##) makes a line a comment.

#SBATCH --job-name=netass_4         # create a short name for your job
#SBATCH --nodes=2                # node count
#SBATCH --ntasks-per-node 10
##SBATCH --nodelist=node[601,602,603]
#SBATCH --cpus-per-task=5        # cpu-cores per task (>1 if multi-threaded tasks)
#SBATCH --mem=50G
#SBATCH --time=30:00:00          # total run time limit (HH:MM:SS)
#SBATCH --mail-type=fail
#SBATCH --mail-type=begin        # send email when job begins
#SBATCH --mail-type=end          # send email when job ends
#SBATCH --mail-user=hyojoonk@cs.princeton.edu


## Create directory in local scratch space (for better disk I/O)
#mkdir -p /scratch/$USER 
#mkdir -p /scratch/$USER/input
#mkdir -p /scratch/$USER/output
#
### copy tshark input
#echo "Start copy tshark csvs"
#cp /n/fs/anonflow/dynamids_data/pcaps_csvs/*.csv /scratch/$USER/input/
#echo "End copy of input"

## Run script
echo `date`": Start of netassay script"
python3 netassay_python_preprocess_dedup_spread.py /n/fs/anonflow/dynamids_data/pcaps/08_19_2020_T20-23 /n/fs/anonflow/netassay_iot/08_19_2020_T20-23
echo `date`": End of netassay script"

### Copy to project space 
#echo "Start of copy output"
#cp -r /scratch/$USER/output/* /n/fs/scratch/$USER/output/
#echo "End of copy output"

## Remove data after copying is done. 
#rm -rf /scratch/$USER/
