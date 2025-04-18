#include "JassAPI.h"

int WAR3MAP_FUNC main()
{
    war3mapcpp::api::DisplayTextToPlayer(war3mapcpp::api::GetLocalPlayer(), 0.f, 0.f, _jstr("Hello World"));

    auto trig = war3mapcpp::api::CreateTrigger();

    auto action = [=] { //
        war3mapcpp::api::DisplayTextToPlayer(war3mapcpp::api::GetLocalPlayer(), 0.f, 0.f, _jstr("PRINT ESC"));
    };
    war3mapcpp::api::TriggerAddAction(trig, action);
    war3mapcpp::api::TriggerRegisterPlayerEvent(trig, war3mapcpp::api::GetLocalPlayer(), war3mapcpp::api::ConvertPlayerEvent(17)); // ESC key

    return 0;
}
