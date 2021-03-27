combined_sim_v1.py -> stages experiment for 15 min
combined_sim_v2.py -> parser/timeout experiment for 15 min

combined_sim_v1_3hr.py -> stages experiment 3 hr
combined_sim_v2_3hr.py -> sparser/timeout experiment for 3 hr

combined_sim_v3_3hr.py -> timeout with memory limits 3 hour
combined_sim_v3_15min.py -> timeout with memory limits 15 min



We're going to want to re-run the stage (memory related) experiments. So that is:
- combined_sim_v1.py
- combined_sim_v1_3hr.py
- combined_sim_v3_15min.py
- combined_sim_v3_3hr.py

With our prescribed data structure fix

These new versions will be stored in the directory "stage_fix_3_27_2021" under the names:
- combined_sim_v1_2.py
- combined_sim_v1_2_3hr.py
- combined_sim_v3_2_15min.py
- combined_sim_v3_2_3hr.py