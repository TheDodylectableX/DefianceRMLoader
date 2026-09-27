// ------------------------------------------------------------
// The interface for (un)installing the hooks from/to the game
// ------------------------------------------------------------
#pragma once

bool HooksInstall();    // Installs all hooks to the game after it runs
void HooksUninstall(); // Removes all hooks cleanly on ASI unload

// ---------------------------------------------------------------------
