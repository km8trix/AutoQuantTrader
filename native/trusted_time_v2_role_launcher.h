#ifndef AQT_TRUSTED_TIME_V2_ROLE_LAUNCHER_H
#define AQT_TRUSTED_TIME_V2_ROLE_LAUNCHER_H

/* The role bootstrap is linked once per fixed executable; there is no dispatch. */
int aqt_trusted_time_v2_role_launcher_main(int argument_count, char **argument_values);

#endif
