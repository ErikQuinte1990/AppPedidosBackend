import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {Llaves} from '../config/llaves';
import {Persona} from '../models/persona.model';
import {PersonaRepository} from '../repositories';

const generador = require("password-generator");
const cryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");


@injectable({scope: BindingScope.TRANSIENT})
export class AutenticacionService {
  constructor(
    @repository(PersonaRepository)
    public personaRepository: PersonaRepository    /* Add @inject to inject parameters */) { }

  /*
   * Add service methods here
   */

  GenerarClave() {
    //the number is password's length and the true value is about the security.

    let clave = generador(8, false);

    return clave;
  }

  CifrarClave(clave: string) {
    let claveCifrada = cryptoJS.MD5(clave).toString();
    return claveCifrada;
  }

  IdentificarPersona(usuario: string, clave: string) {
    try {
      let p = this.personaRepository.findOne({where: {correo: usuario, clave: clave}});
      if (p) {
        return p;
      }
      return false;
    } catch {
      return false;
    }
  }

  GenerarTokenJWT(persona: Persona) {
    let token = jwt.sing({
      data: {
        id: persona.id,
        correo: persona.correo,
        nombre: persona.nombres + " " + persona.apellidos
      }
    },
      Llaves.claveJWt);
    return token;
  }

  ValidarTokenJWT(token: string) {
    try {
      let datos = jwt.verify(token, Llaves.claveJWt);
      return datos;
    } catch {
      return false;
    }
  }
}
