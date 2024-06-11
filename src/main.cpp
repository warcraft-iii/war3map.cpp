#include "JassAPI.h"

int WAR3MAP_FUNC main()
{
    war3mapcpp::api::DisplayTextToPlayer(war3mapcpp::api::GetLocalPlayer(), 0.f, 0.f, _jstr("Hello World"));
    return 0;
}
