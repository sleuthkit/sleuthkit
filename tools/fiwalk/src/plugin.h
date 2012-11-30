#ifndef PLUGIN_H
#define PLUGIN_H

void config_read(const char *fname);
bool plugin_match(const std::string &fname);
void plugin_process(const std::string &fname);


#endif
