// Define EXPLICIT_RB_INIT if you want to call rb_init() manually,
// instead of having it called by the loader
#ifdef EXPLICIT_RB_INIT
extern "C" void rb_init();
#endif
extern "C" void rb_xcheck(unsigned long item);
