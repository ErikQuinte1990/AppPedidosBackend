import {AuthenticationStrategy} from '@loopback/authentication';
import {service} from '@loopback/core/dist/service';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {AutenticacionService} from '../services';


export class EstrategiaAdmnistrador implements AuthenticationStrategy {
  name: string = 'admin';

  constructor(
    @service(AutenticacionService)
    public servicionAutenticacion: AutenticacionService
  ) { }

  async authenticate(request: Request): Promise<UserProfile | undefined> {
    let token = parseBearerToken(request);
    if (token) {
      let datos = this.servicionAutenticacion.ValidarTokenJWT(token);
      if (datos) {
        let perfil: UserProfile = Object.assign({
          nombre: datos.data.nombre
        });
        return perfil;

      } else {
        throw new HttpErrors[401]("El token incluido no es válido.")
      }

    } else {
      throw new HttpErrors[401]("No se ha incluido un token en la solicitud.")
    }
  }

}
