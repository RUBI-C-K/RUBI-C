#include "rubic_core.h"

int main(int argc, char* argv[]) {
    try {
        // AVISO DE RESPONSABILIDAD 
        std::cout << GREEN << "rubi-c es un codigo abierto y de uso libre no me responsabiliso por el mal uso de la herramiento o perdida de datos es una herramienta en fase alpha\n" << RESET << std::endl;
        
        // Verificar si tenemos sudo
        if (geteuid() != 0) {
            std::cout << YELLOW << "Se requieren permisos de administrador" << RESET << std::endl;
            std::cout << CYAN << "Reiniciando con sudo..." << RESET << std::endl;
            
            // Reconstruir con sudo
            std::string cmd = "sudo ";
            cmd += argv[0];
            
            for (int i = 1; i < argc; i++) {
                cmd += " '" + std::string(argv[i]) + "'";
            }
            
            int ret = system(cmd.c_str());
            return ret;
        }
        
        // Ya hay sudo, continuar normalmente
        std::cout << "\033[2J\033[1;1H";
        Memguardin::lockProcess();
        CrashHnd::setup();

        UserMgr um;
        um.run();
    } 
    catch (const std::exception& e) {
        std::cerr << RED << "\n✗ ERROR: " << e.what() << RESET << std::endl;
        Memguardin::unlockProcess();
        return 1;
    }
    catch (...) {
        std::cerr << RED << "\n✗ ERROR DESCONOCIDO" << RESET << std::endl;
        Memguardin::unlockProcess();
        return 1;
    }

    Memguardin::unlockProcess();
    return 0;
}
