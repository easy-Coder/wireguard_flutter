#ifndef WIREGUARD_FLUTTER_SERVICE_CONTROL_H
#define WIREGUARD_FLUTTER_SERVICE_CONTROL_H

#include <string>

namespace wireguard_flutter {

struct CreateArgs {
  std::wstring description, executable_and_args, dependencies;
};

class ServiceControl {
 public:
  const std::wstring service_name_;

  ServiceControl(const std::wstring service_name) : service_name_(service_name) {}

  void CreateAndStart(CreateArgs args);
  void Stop();
  void Disable();
  std::string GetStatus();
};

}  // namespace wireguard_dart

#endif
