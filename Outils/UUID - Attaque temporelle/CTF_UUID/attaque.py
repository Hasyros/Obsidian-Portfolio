import time_uuid, calendar, time
from datetime import datetime
import uuid


def convert():
 # Let's put here the data of admin registration time without milliseconds
 dt_obj = datetime.strptime('11.02.2026 03:10:14,0', '%d.%m.%Y %H:%M:%S,%f')
 millisec = dt_obj.timestamp() 
 return millisec

# To verify. Timestamp your registration. It doesn't have to be
user_time = 1770775814.71700

# Add milliseconds to the admin registration timestamp
adm_man_time = convert() + 0.714011

print("user_timestamp:",user_time)
print("manl_timestamp:",adm_man_time)
user_uuids = time_uuid.TimeUUID.convert(user_time)
admn_man_uuids = time_uuid.TimeUUID.convert(adm_man_time)

# Let's check the first 2 blocks of UUID and compare it with the one received at registration
print("user_uuid:", user_uuids)

# Get admin UUIDs
for i in range(1, 10):
 adm_man_time += i/10000000
 admn_man_uuids = time_uuid.TimeUUID.convert(adm_man_time)
 print("*admin_uuid:", admn_man_uuids)