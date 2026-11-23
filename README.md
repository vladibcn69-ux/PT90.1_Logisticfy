# [PE 90.1] Logisticfy — Propuesta de prevención y concienciación en ciberseguridad

**Módulo:** MF0490 · **Autor:** Volodymyr Osebchuk · **Entrega:** AEA1 (fecha límite: miércoles 25 de noviembre de 2026, 12 h)

> **Nota de lectura.** Este documento es un **diseño de propuesta**. Todas las medidas, normas y acciones descritas son *propuestas* y no se presentan como controles ya implantados en Logisticfy. Tampoco se muestran resultados de actividades de concienciación, porque no se han ejecutado. Los hechos proceden de la documentación *[PE 90.1] Logisticfy*; lo demás se marca como **supuesto** o **propuesta**.

---

## 1. Marco de protección de Logisticfy

### 1.1. Análisis del contexto y necesidades de protección

**Resumen del contexto (hechos documentados).** Logisticfy es una startup logística B2B ficticia de Barcelona que presta un *servicio de gestión logística* a unos 25 clientes empresariales, con entre 80 y 120 expediciones diarias. El transporte físico lo realizan tres transportistas externos. La plantilla es de 20 personas (19 empleados y una persona en prácticas) repartidas en Dirección, Operaciones, Atención al Cliente, Tecnología/IT, Comercial y Administración. El negocio sigue este ciclo: creación de expediciones → validación → asignación de transportista → seguimiento → incidencias → facturación. Un mismo dato de envío circula por varios procesos (prestar el servicio, responder consultas y facturar), y parte de la información (contactos, destinatarios, direcciones de entrega) se refiere a personas aunque el negocio sea B2B.

**Qué activos se priorizan y por qué.** No se analizan los trece activos, solo los que sostienen el ciclo de la expedición y concentran la información más sensible. No se asignan criticidades ni se hace evaluación de riesgos, como indica el enunciado.

| ID | Nombre | Justificación (necesidad de protección) | Relación con procesos / funciones |
|---|---|---|---|
| DAT-01 | Base de datos de clientes, envíos y facturación | Contiene toda la información de negocio y datos de personas (contactos, destinatarios, direcciones). Necesita **confidencialidad** (datos de clientes), **integridad** (un envío o factura alterados causan errores operativos y económicos) y **disponibilidad** (sin ella no se tramitan expediciones). | Todos los procesos: creación, validación, seguimiento, incidencias y facturación. Operaciones, Atención al Cliente y Administración. |
| SW-01 | Plataforma web y backoffice (portal de clientes) | Es el punto de entrada de los clientes (exposición a Internet) y la herramienta interna de trabajo. Necesita control de acceso, integridad de las operaciones y disponibilidad. | Creación de expediciones por el cliente; validación y gestión por Operaciones; consulta de incidencias por Atención al Cliente. |
| SW-02 | API de integración con transportistas | Intercambia información de envíos con terceros; un fallo de autenticación o validación afecta a la integridad de los estados y a la confidencialidad de los datos compartidos. | Asignación de transportistas y seguimiento de envíos. |
| EXT-01 | Integraciones con tres transportistas externos | Dependencia de terceros que reciben y devuelven datos de expediciones; la seguridad depende también de ellos. | Asignación y seguimiento; atención de incidencias del servicio. |
| IAM-01 | Identidades y mecanismos de acceso | Quien controla las cuentas controla los datos. Las cuentas con mucho acceso (backoffice, administración de sistemas) requieren especial cuidado. | Transversal: acceso de personal y clientes a SW-01, DAT-01 e INF-01. |
| HW-01 | Equipos Windows 11 del personal | Son el lugar donde se abre el correo, se usa el backoffice y se manejan datos; son la vía habitual de entrada de malware. | Trabajo diario de las seis áreas. |
| COM-01 | Correo corporativo (servicio externo) | Principal canal de comunicación con clientes, transportistas y proveedores, y vector habitual de phishing y fraude de facturas. | Atención al Cliente, Comercial, Administración, Dirección. |
| BKP-01 | Copias de seguridad | Permiten recuperar información y servicio tras un incidente o error. | Continuidad de todo el ciclo; en especial DAT-01. |
| MON-01 | Registros y sistema de monitorización | Permiten detectar actividad anómala y reconstruir lo ocurrido (aplicación, sistema, autenticación). | Soporte técnico (IT) y respuesta a incidentes. |

*Activos no desarrollados* (se citan solo como contexto): INF-01 (servidor Ubuntu), SW-03 (repositorios), NET-01 (red de oficina) y PHY-01 (oficina); se tratan de forma indirecta en la normativa (apartado 1.3).

**Funciones relevantes y sus activos.**

| Proceso / función | Activos que lo soportan | Personal implicado |
|---|---|---|
| Creación de expediciones (cliente) | SW-01, DAT-01, IAM-01 | Clientes; Operaciones |
| Validación y gestión de solicitudes | SW-01, DAT-01, HW-01 | Operaciones |
| Asignación de transportistas y seguimiento | SW-02, EXT-01, DAT-01 | Operaciones, IT |
| Atención de incidencias | SW-01, COM-01, DAT-01 | Atención al Cliente, Operaciones |
| Facturación | DAT-01, COM-01, HW-01 | Administración |
| Sostenimiento técnico | INF-01, BKP-01, MON-01, SW-03, IAM-01 | Tecnología/IT |

**Hechos, supuestos y propuestas.** Es un *hecho documentado* que estos activos existen y la función que cumplen. Es un *supuesto* que contienen datos de personas y que existen cuentas con privilegios de administración. **No** se sabe qué controles existen hoy (autenticación multifactor, cifrado de copias, etc.); su ausencia en la documentación no demuestra incumplimiento.

---

### 1.2. Principios generales de ciberseguridad

Los principios orientan las decisiones de seguridad. Las reglas concretas para el trabajo diario se desarrollan en el apartado 1.3.

| ID | Principio | Aplicación en Logisticfy (propuesta) | Relación con procesos, funciones o activos |
|---|---|---|---|
| P-01 | **Proteger la información de clientes y envíos** (confidencialidad, integridad y disponibilidad). | Los datos de clientes, destinatarios y facturación se tratan como información de negocio protegida durante todo su ciclo: se recogen, usan y conservan solo para prestar el servicio. | DAT-01, SW-01; todo el ciclo de la expedición, incluidos los datos de personas de contacto y destinatarios. |
| P-02 | **Mínimo privilegio y necesidad de conocer.** | Cada persona accede únicamente a lo que necesita para su puesto. Los permisos se conceden según la función y se retiran al cambiar de puesto o dejar la empresa. | IAM-01 sobre SW-01 y DAT-01. Facturación solo para Administración; gestión de expediciones para Operaciones. |
| P-03 | **Identidad personal y autenticación robusta.** | Cada persona tiene su cuenta personal e intransferible; se usa autenticación reforzada en los accesos más sensibles. | IAM-01; backoffice (SW-01) y administración de INF-01. |
| P-04 | **Uso profesional y autorizado de equipos, software y canales.** | El trabajo con datos de la empresa se hace en equipos y herramientas corporativos autorizados y con el correo corporativo. | HW-01, COM-01, SW-01. |
| P-05 | **Seguridad compartida con terceros.** | Los intercambios con transportistas se hacen solo por los canales acordados y con las credenciales asignadas; se comparten solo los datos necesarios. | SW-02, EXT-01; asignación y seguimiento de envíos. |
| P-06 | **Resiliencia y recuperación.** | La información importante se copia y la capacidad de restaurar se comprueba periódicamente. | BKP-01, DAT-01, INF-01; continuidad de las 80–120 expediciones diarias. |
| P-07 | **Trazabilidad y comunicación temprana de anomalías, sin represalias.** | Se registra la actividad relevante y todo el personal comunica rápidamente lo que parezca sospechoso, sin culpabilizar. | MON-01; todo el personal. |
| P-08 | **Responsabilidad compartida y concienciación continua.** | La seguridad es tarea de todos, con un responsable visible y formación adaptada a cada función. | Las seis áreas, incluida la persona en prácticas. |

**Coherencia del conjunto.** P-01 define *qué* se protege; P-02 y P-03 *quién accede*; P-04 y P-05 *con qué medios y con quién se trabaja*; P-06 y P-07 la capacidad de *recuperarse y reaccionar*; y P-08 el factor humano, que sustenta el programa del Bloque 02.

#### Conocimiento y respaldo de Dirección

*(Todo lo siguiente es una **propuesta**. El respaldo de Dirección **todavía no se ha producido**.)*

1. **Presentación.** El responsable de IT, como consultor interno de referencia, presentaría los principios al CEO y al responsable de operaciones en una reunión de unos 30 minutos, con una síntesis de una página que incluya los ocho principios y su relación con el negocio (ciclo de la expedición y datos de clientes).
2. **Constancia del respaldo.** Dirección revisaría y, si procede, aprobaría los principios mediante un acta breve de reunión firmada por el CEO y el responsable de operaciones, con fecha y versión del documento. Se guardaría en el repositorio documental corporativo con control de versiones.
3. **Comunicación al personal.** Una vez aprobados, el CEO enviaría una comunicación interna por correo corporativo, con los principios resumidos en una página. Se repasarían en la sesión de bienvenida de las nuevas incorporaciones y en la primera sesión del programa (acción A-01 del Bloque 02). Se pediría a cada persona una confirmación de lectura.
4. **Revisión.** Dirección revisaría los principios una vez al año o ante cambios importantes (nuevo transportista, nuevo sistema o incidente grave).

---

### 1.3. Normativa de protección del puesto de trabajo

**Ámbito de aplicación (propuesta).** La normativa se aplica a **las 20 personas de la plantilla** (Dirección, Operaciones, Atención al Cliente, Tecnología/IT, Comercial, Administración y la persona en prácticas) y a cualquier persona externa con acceso a los sistemas o a la oficina de Logisticfy. Se aplica a los equipos HW-01, a las aplicaciones SW-01 y SW-02, al correo COM-01, a las cuentas y accesos IAM-01, a los datos de DAT-01 y sus copias BKP-01, a los registros MON-01 y a los espacios de PHY-01.

**Responsabilidades generales (propuesta).**

| Función | Responsabilidad |
|---|---|
| Dirección (CEO y responsable de operaciones) | Aprobar la normativa, respaldar su cumplimiento y autorizar excepciones de riesgo alto. |
| Responsable de IT | Coordinar la aplicación, mantener la normativa y gestionar la comunicación de anomalías. |
| Administrador de sistemas | Aplicar las medidas técnicas (cuentas, copias, registros) y las comprobaciones técnicas. |
| Responsables de área (Operaciones, Atención al Cliente, Comercial, Administración) | Aplicar y supervisar las normas en su equipo y solicitar o retirar permisos. |
| Todo el personal | Cumplir las normas, completar la formación y comunicar anomalías. |

**Normas.**

| ID | Regla concreta | Personal afectado | Aplicación y comprobación | Tratamiento / excepciones |
|---|---|---|---|---|
| **Identidades y accesos** | | | | |
| N-01 | Cada persona usa **solo su cuenta personal**. No se comparten usuarios ni contraseñas, ni siquiera con compañeros o con IT. | Todo el personal | *Aplicación:* altas nominales. *Comprobación:* revisión trimestral de cuentas genéricas o compartidas por el administrador de sistemas. | Si un servicio solo admite una cuenta común, requiere autorización por escrito del responsable de IT y un registro de quién la usa. |
| N-02 | Las contraseñas tienen **como mínimo 12 caracteres**, son únicas para cada servicio corporativo y se guardan en el gestor de contraseñas autorizado. No se anotan en papel ni se reutilizan las personales. | Todo el personal | *Aplicación:* gestor corporativo facilitado por IT; política de contraseña en los sistemas que lo permitan. *Comprobación:* configuración revisada por IT; muestreo en las sesiones de formación. | Sin excepciones para cuentas con acceso a DAT-01. |
| N-03 | Se activa **autenticación multifactor (MFA)** en el correo corporativo, el backoffice y cualquier acceso de administración, cuando el servicio lo permita. | Todo el personal con acceso; con carácter prioritario IT y Administración | *Aplicación:* activación guiada por IT. *Comprobación:* informe del estado de MFA por cuenta. | Si un servicio no admite MFA: control compensatorio aprobado por el responsable de IT (por ejemplo, restricción de acceso) y revisión semestral. |
| N-04 | Los permisos se asignan **según la función** (mínimo privilegio) y los pide el responsable de área. Al cambiar de puesto o dejar la empresa se **revisan o retiran el mismo día**. | Responsables de área, IT, Administración y Dirección | *Aplicación:* solicitud registrada (ticket). *Comprobación:* revisión semestral de permisos en el backoffice y cuentas de DAT-01. | Permisos temporales: caducidad máxima acordada y registrada. |
| N-05 | Las cuentas de **administración** se usan solo para tareas de administración, y no para el trabajo diario (correo, navegación). | Administrador de sistemas y responsable de IT; persona en prácticas solo con supervisión | *Aplicación:* cuenta distinta para administrar. *Comprobación:* revisión de los registros de acceso (MON-01). | Acceso de emergencia: se documenta y se revisa después. |
| **Equipos y software** | | | | |
| N-06 | Se trabaja solo con **equipos corporativos** (HW-01) y software autorizado. No se instala software no autorizado ni se desactivan el antivirus, las actualizaciones o el cifrado. | Todo el personal | *Aplicación:* configuración centralizada por IT. *Comprobación:* inventario de software y revisión del estado de actualizaciones por IT. | Software nuevo: solicitud al responsable de IT; la aprobación queda registrada. |
| N-07 | El equipo se **bloquea** al ausentarse (Windows + L) y se activa el bloqueo automático por inactividad (máx. 5 minutos). | Todo el personal | *Aplicación:* política de bloqueo en HW-01. *Comprobación:* rondas visuales y revisión de la política. | Pantallas compartidas de monitorización: valoración por IT. |
| N-08 | Los **dispositivos personales** no se usan para acceder a DAT-01 ni al backoffice; el correo corporativo en el móvil personal solo con autorización. | Todo el personal | *Aplicación:* acceso restringido a equipos corporativos. *Comprobación:* revisión de accesos y dispositivos registrados. | Uso autorizado por escrito por el responsable de IT, con medidas mínimas (bloqueo, cifrado). |
| **Protección de la información** | | | | |
| N-09 | Los datos de clientes, destinatarios y facturación se consultan y tratan **solo si es necesario** para la tarea. **No se copian** a fuentes no autorizadas (USB personales, mensajería personal, nubes personales, hojas de cálculo locales). | Operaciones, Atención al Cliente, Administración, Comercial | *Aplicación:* trabajar siempre sobre el backoffice. *Comprobación:* revisión de accesos a DAT-01 (MON-01) y control de exportaciones. | Exportación puntual necesaria: aprobada por el responsable de área, con borrado posterior. |
| N-10 | La información se **clasifica** de forma simple (*pública*, *interna*, *confidencial*) y se trata según su etiqueta. Se considera *confidencial* todo dato de clientes, destinatarios, facturación y credenciales. | Todo el personal | *Aplicación:* etiquetado en documentos y plantillas. *Comprobación:* muestreo semestral por IT. | Dudas: se trata como confidencial y se consulta a IT. |
| N-11 | Los documentos en papel con datos de clientes se **guardan bajo llave** al terminar la jornada y se destruyen con la trituradora. | Operaciones, Administración, Atención al Cliente | *Aplicación:* mobiliario con llave y trituradora. *Comprobación:* ronda de fin de jornada. | Ninguna. |
| N-12 | **Copias de seguridad:** la información de trabajo se guarda en los **repositorios corporativos** (no en el disco local) para que quede cubierta por BKP-01. IT comprueba **cada trimestre** que se puede restaurar. | Todo el personal; IT | *Aplicación:* carpetas corporativas. *Comprobación:* prueba de restauración trimestral documentada. | Archivos locales temporales: no se admiten como única copia. |
| **Comunicaciones** | | | | |
| N-13 | Se usa **solo el correo corporativo** (COM-01) y los canales acordados para tratar con clientes y transportistas. **Nunca** se envían contraseñas, y los datos sensibles se envían solo al destinatario verificado. | Todo el personal | *Aplicación:* revisión de destinatarios antes de enviar. *Comprobación:* muestreo de comunicaciones e incidencias de envío erróneo. | Canal alternativo: autorización del responsable de área. |
| N-14 | **Ante un correo o llamada con petición inusual** (cambio de IBAN, datos de acceso, urgencia, enlaces o archivos inesperados) se **verifica por un segundo canal** (llamada a un teléfono ya conocido) antes de actuar. **No** se hace clic en enlaces sospechosos. | Administración, Atención al Cliente, Comercial, Operaciones, Dirección | *Aplicación:* procedimiento de verificación en la guía M-01. *Comprobación:* simulacros y registro de los casos comunicados. | Ninguna para cambios de datos de pago. |
| N-15 | Los **transportistas** acceden solo mediante SW-02 con las credenciales asignadas; se les comparte únicamente la información necesaria para el envío. | Operaciones, Tecnología/IT (incluido el desarrollador) | *Aplicación:* credenciales individuales por transportista. *Comprobación:* revisión semestral de accesos e integraciones. | Cualquier nuevo canal con un transportista requiere la aprobación de IT. |
| **Seguridad física** | | | | |
| N-16 | **Control de acceso físico:** las visitas se registran, van acompañadas y no se dejan solas en zonas de trabajo. Las puertas no se dejan abiertas y no se permite entrar a desconocidos detrás de uno mismo. | Todo el personal | *Aplicación:* registro de visitas. *Comprobación:* revisión mensual del registro. | Accesos de proveedores: acordados previamente con el responsable de IT. |
| N-17 | **Mesa limpia:** al terminar la jornada no se dejan documentos con datos, notas con contraseñas ni dispositivos sin vigilancia a la vista. | Todo el personal | *Aplicación:* hábito de cierre. *Comprobación:* ronda de fin de jornada. | Ninguna. |
| **Comunicación de anomalías** | | | | |
| N-18 | Se comunica **de inmediato** al responsable de IT (canal único de aviso) cualquier sospecha: correo extraño, equipo con comportamiento raro, pérdida de equipo o documentación, acceso no reconocido, envío de datos a un destinatario equivocado. **No se sanciona** a quien comunica de buena fe. | Todo el personal | *Aplicación:* buzón y teléfono de aviso; guía rápida. *Comprobación:* registro de avisos y tiempo de respuesta. | Si es dudoso, se avisa de todas formas. |
| N-19 | Ante una sospecha, **no se borra nada** ni se intenta arreglar por cuenta propia; se desconecta el equipo de la red (si es seguro hacerlo) y se espera la indicación de IT. | Todo el personal | *Aplicación:* instrucciones en M-01. *Comprobación:* revisión de los casos comunicados. | Ninguna. |

#### Comunicación y revisión de la normativa

*(Propuesta.)*

- **Comunicación.** Tras la aprobación por Dirección, la normativa se difunde por correo corporativo, con un resumen de una página. Se presenta en la primera sesión del programa (A-01) y se entrega a las nuevas incorporaciones el primer día. Cada persona confirma su lectura y la confirmación queda registrada.
- **Excepciones.** Quien necesite una excepción lo solicita por escrito (ticket o correo) al responsable de IT, indicando el motivo, la duración y las medidas compensatorias. El responsable de IT autoriza las de riesgo bajo; las que afecten a DAT-01 o a cuentas de administración las autoriza Dirección. Se registran, tienen fecha de caducidad y se revisan cada seis meses.
- **Revisión.** La normativa se revisa **una vez al año** o ante un cambio relevante (incidente, nuevo sistema, nuevo transportista o cambios de plantilla). Las versiones se numeran y el cambio se comunica al personal.
- **Alcance de la comprobación.** Las comprobaciones indicadas son propuestas de seguimiento. La auditoría efectiva del cumplimiento queda para AEA2.


---

> **Estado de la entrega:** este commit incluye el **Bloque 01 (Marco de protección)**. El Bloque 02 (Programa de concienciación), el Bloque 03 (Material M-01) y el apartado 4 (Fuentes, supuestos y autoría) se añadirán en el siguiente commit.
