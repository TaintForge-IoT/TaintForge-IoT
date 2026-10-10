#include <stdio.h>
#include <unistd.h>

__attribute__((constructor)) static void loaded(void) {
    fputs("[CU-GUARD] solver checks forbidden\n", stderr);
}

static void forbidden(const char *api) {
    fprintf(stderr, "[CU-GUARD] FORBIDDEN %s\n", api);
    _exit(125);
}

int Z3_solver_check(void *context, void *solver) {
    (void)context;
    (void)solver;
    forbidden("Z3_solver_check");
    return 0;
}

int Z3_solver_check_assumptions(void *context, void *solver, unsigned count, void *assumptions) {
    (void)context;
    (void)solver;
    (void)count;
    (void)assumptions;
    forbidden("Z3_solver_check_assumptions");
    return 0;
}
