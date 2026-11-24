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

## 2. Programa de concienciación

### 2.1. Objetivos y destinatarios

| ID | Conducta o conocimiento que se pretende mejorar | Departamento o perfil | Relación con las necesidades de Logisticfy |
|---|---|---|---|
| O-01 | **Reconocer y comunicar correos, llamadas y mensajes sospechosos** (phishing, fraude de pagos, suplantación de clientes o transportistas) y verificar por un segundo canal. | Atención al Cliente, Administración, Comercial, Operaciones, Dirección; también la persona en prácticas | Estas áreas manejan a diario COM-01 y recibirían la mayoría de los intentos de engaño; Administración, además, trabaja con datos de facturación (DAT-01). |
| O-02 | **Gestionar contraseñas y cuentas de forma segura** (cuenta personal, contraseñas únicas, gestor y MFA). | Todo el personal | Una cuenta comprometida da acceso a SW-01 y DAT-01 (IAM-01). |
| O-03 | **Tratar los datos de clientes y envíos con el criterio de necesidad** (no copiar, no enviar a destinatarios no verificados, clasificar). | Operaciones, Atención al Cliente, Administración, Comercial | Estas áreas manejan datos de clientes, destinatarios y facturación (DAT-01). |
| O-04 | **Aplicar las medidas técnicas y de acceso del puesto** (equipos, privilegios, copias, integraciones con transportistas, registros). | Tecnología/IT (responsable, administrador, desarrollador, persona en prácticas) | IT sostiene INF-01, BKP-01, MON-01, SW-02 y SW-03, y tiene los privilegios más altos. |
| O-05 | **Comunicar rápido las anomalías y actuar con calma** (qué hacer y qué no hacer). | Todo el personal | La detección temprana limita el impacto de cualquier incidente (MON-01, norma N-18). |
| O-06 | **Respaldar y dar ejemplo** (conocer los principios, autorizar excepciones con criterio). | Dirección y responsables de área | Sin el respaldo visible de Dirección el resto de acciones pierde eficacia (P-08). |

**Justificación.** Los objetivos priorizan los comportamientos con más impacto en el ciclo de la expedición. Atención al Cliente, Administración y Comercial están más expuestas al engaño por correo; Operaciones y Administración tratan los datos; IT concentra los privilegios técnicos; la persona en prácticas recibe formación inicial y supervisión. Dirección actúa como patrocinadora. Todos los objetivos son *observables*.

### 2.2. Plan de acciones de concienciación

| ID | Objetivo | Destinatarios | Acción y canal | Temporalización | Responsable | Material |
|---|---|---|---|---|---|---|
| A-01 | O-01, O-05 | Todo el personal, con ejemplos específicos para Atención al Cliente, Administración y Comercial | **Taller presencial «Reconoce y comunica»** de 60 minutos: presentación de la normativa, casos reales ficticios de Logisticfy y cuestionario final. Se reparte la guía de bolsillo. Presencial, en la sala de reuniones. | Semana 1 del programa; se repite en una sesión corta para nuevas incorporaciones | Responsable de IT | **M-01** (guía de bolsillo y cuestionario) |
| A-02 | O-02 | Todo el personal | **Sesión práctica de 30 minutos:** configurar el gestor de contraseñas y activar MFA con ayuda de IT. | Semana 2 | Responsable de IT y administrador de sistemas | Guía paso a paso (a desarrollar) |
| A-03 | O-03 | Operaciones, Atención al Cliente, Administración, Comercial | **Microformación de 20 minutos** sobre clasificación y tratamiento de datos, con 3 casos prácticos (envío al destinatario equivocado, copia en USB, consulta innecesaria). | Semana 3 | Responsables de área, con apoyo de IT | Presentación breve y casos (a desarrollar) |
| A-04 | O-04 | Tecnología/IT | **Sesión técnica de 90 minutos:** revisión de permisos, prueba de restauración de BKP-01, buenas prácticas de integración con transportistas y revisión de registros de MON-01. | Semana 4; la prueba de restauración se repite cada trimestre | Responsable de IT | Lista de comprobación (a desarrollar) |
| A-05 | O-01, O-05 | Todo el personal | **Simulacro de correo sospechoso** inofensivo (ficticio) y recordatorio mensual por correo interno de 5 líneas. | Un simulacro trimestral; recordatorio mensual | Responsable de IT | Plantilla de simulacro y recordatorios (a desarrollar) |
| A-06 | O-06 | Dirección y responsables de área | **Reunión de 30 minutos** para presentar principios y normativa, y registrar el respaldo (ver 1.2). | Antes de la Semana 1 | Responsable de IT, con el CEO | Resumen de una página (a desarrollar) |

*Solo se desarrolla M-01 en el Bloque 03. Los demás materiales quedan como previstos.*

### 2.3. Seguimiento y evaluación del programa

*(Diseño del seguimiento; no hay resultados, porque el programa no se ha ejecutado.)*

| Objetivo / acción | Qué se medirá (indicador) | Cómo se comprobaría (evidencia) | Cuándo |
|---|---|---|---|
| O-01 / A-01 | % de asistentes que superan el cuestionario (≥ 80 % de aciertos) | Resultados del cuestionario de M-01; hoja de asistencia | Al finalizar el taller |
| O-01 / A-05 | % de personas que comunican el simulacro; % que pulsan el enlace; tiempo medio hasta el aviso | Registro del buzón de avisos y del simulacro | Tras cada simulacro (trimestral) |
| O-02 / A-02 | % de cuentas con MFA y con gestor de contraseñas | Informe de IT por cuenta | Al mes de la sesión, y semestral |
| O-03 / A-03 | Número de incidentes por envío erróneo o copia no autorizada; resultado de los casos prácticos | Registro de incidencias; revisión de accesos y exportaciones (MON-01) | Trimestral |
| O-04 / A-04 | Prueba de restauración realizada y superada; permisos revisados | Acta de la prueba; informe de permisos | Trimestral |
| O-05 | Número de avisos de anomalías y tiempo entre la detección y el aviso | Registro de avisos | Trimestral |
| O-06 / A-06 | Respaldo de Dirección registrado y comunicado | Acta firmada y correo de comunicación | Una vez, y revisión anual |
| Satisfacción | Utilidad percibida (escala 1–5) | Mini encuesta anónima tras cada acción | Tras cada acción |

**Revisión y mejora.** Cada trimestre el responsable de IT presentaría a Dirección un informe de una página con los indicadores. Si un indicador no alcanza el umbral (por ejemplo, aprobados < 80 % o más del 20 % de clics en un simulacro), se repetiría la acción con otro formato, se reforzaría el mensaje en el equipo afectado y se ajustarían los contenidos con los casos comunicados. Una vez al año se revisaría el programa completo junto con la normativa.

---

## 3. Desarrollo del material de concienciación

### 3.1. Material desarrollado

- **ID del material:** M-01
- **Título:** «Guía de bolsillo: reconoce, verifica y comunica» (Logisticfy)
- **Formato:** guía breve de una página, más cuestionario con soluciones (texto en Markdown), para uso impreso y digital

#### Contenido del material

---

#### GUÍA DE BOLSILLO · Reconoce, verifica y comunica

**Para:** todo el personal de Logisticfy (en especial Atención al Cliente, Administración, Comercial y Operaciones)  
**Versión:** 1.0 (ficticia, para formación) · **Contacto de seguridad:** responsable de IT (buzón de avisos de seguridad)

**1. ¿Por qué nos importa?**

Cada día recibimos correos y llamadas de clientes, transportistas y proveedores sobre envíos, incidencias y facturas. Los delincuentes se aprovechan de ello. Un solo clic o una sola transferencia equivocada pueden dar acceso a datos de clientes o provocar pérdidas económicas. **No hace falta ser técnico: hace falta parar un momento.**

**2. Las 5 señales de alarma**

| # | Señal | Ejemplo en Logisticfy |
|---|---|---|
| 1 | **Urgencia o presión** | «El envío queda retenido si no confirmas hoy los datos de pago». |
| 2 | **Remitente que no cuadra** | El correo dice ser de un transportista, pero la dirección tiene una letra cambiada (`transp0rtista.com`). |
| 3 | **Petición inusual** | «Ha cambiado nuestro IBAN, factura a esta cuenta a partir de ahora». |
| 4 | **Enlace o adjunto inesperado** | Una «factura» o «albarán» que nadie ha solicitado. |
| 5 | **Petición de credenciales o códigos** | «Introduce tu usuario y contraseña para ver la incidencia». *Nadie legítimo pide tu contraseña ni el código MFA.* |

**3. Qué hacer: la regla PARA-VERIFICA-AVISA**

1. **PARA.** No hagas clic, no abras el adjunto, no respondas, no hagas la transferencia.
2. **VERIFICA por otro canal.** Llama al **teléfono que ya tienes registrado** del cliente o transportista (nunca el que aparece en el mensaje sospechoso).
3. **AVISA.** Comunica el caso al responsable de IT (buzón de avisos). Reenvía el correo como adjunto y cuenta qué hiciste. **Avisar siempre es mejor que callar, y nadie será sancionado por comunicar de buena fe.**

**4. Si ya has hecho clic o has dado datos**

- **No te asustes ni borres nada.**
- Desconecta el equipo de la red (cable o Wi-Fi) si puedes.
- Avisa de inmediato al responsable de IT. Cuanto antes se sepa, menos daño.
- Si has escrito una contraseña, **cámbiala** desde otro equipo cuando IT lo indique.

**5. Tres casos de Logisticfy**

**Caso A — Administración.** Llega un correo de un cliente: «Hemos cambiado de banco; haz el próximo reembolso a este IBAN». → *Verifica llamando al teléfono registrado. No cambies datos de pago por correo.*

**Caso B — Atención al Cliente.** Un supuesto destinatario llama pidiendo la dirección de entrega y el nombre de contacto de otro cliente «para recoger el paquete». → *No des datos si no puedes comprobar que es el cliente titular; consulta con Operaciones.*

**Caso C — Operaciones.** Un correo de «Transportes Rápidos» (nombre ficticio) pide credenciales de SW-02 «para actualizar la integración». → *Las credenciales no se envían nunca por correo; avisa a IT.*

**6. Cinco hábitos cada día**

1. Mi cuenta es **personal**; mi contraseña, **única**, y el **MFA**, activado.
2. **Bloqueo** el equipo (Windows + L) siempre que me levanto.
3. Solo uso el **correo corporativo** y las herramientas autorizadas.
4. Los datos de clientes **no salen** de los sistemas corporativos.
5. **Ante la duda, pregunto.**

*Normas relacionadas: N-01, N-02, N-03, N-07, N-09, N-13, N-14, N-18, N-19.*

---

#### CUESTIONARIO FINAL (10 preguntas, 10 minutos)

*Marca una opción por pregunta. Aprobado: 8 aciertos o más.*

1. Recibes un correo de un cliente que te pide cambiar el IBAN de pago. ¿Qué haces?
   - a) Lo cambio, porque el cliente lo pide.
   - b) Respondo al correo para confirmar.
   - c) Llamo al teléfono que ya tengo registrado del cliente y verifico.
   - d) Lo reenvío a un compañero.
2. ¿Cuál es una señal típica de phishing?
   - a) Un saludo con tu nombre.
   - b) Urgencia y presión para actuar ya.
   - c) Un mensaje de un compañero conocido.
   - d) Un correo sin adjuntos.
3. ¿Puede alguien legítimo (IT o un proveedor) pedirte tu contraseña o el código MFA?
   - a) Sí, si es urgente.
   - b) Sí, si es de IT.
   - c) No, nunca.
   - d) Solo por teléfono.
4. Has hecho clic en un enlace sospechoso. ¿Qué haces primero?
   - a) Borro el correo y sigo trabajando.
   - b) Aviso a IT de inmediato, sin borrar nada.
   - c) Espero a ver si pasa algo.
   - d) Lo comento por el chat personal.
5. ¿Dónde se guarda el trabajo con datos de clientes?
   - a) En un USB personal.
   - b) En el escritorio del equipo.
   - c) En los repositorios corporativos.
   - d) En mi nube personal.
6. Una persona llama pidiendo los datos de entrega de un envío que no es suyo. ¿Qué haces?
   - a) Se los doy, parece amable.
   - b) No los doy y consulto con Operaciones.
   - c) Se los envío por mensajería personal.
   - d) Se los doy si me da su nombre.
7. Te vas a tomar un café. ¿Qué haces con el equipo?
   - a) Nada, vuelvo enseguida.
   - b) Lo bloqueo (Windows + L).
   - c) Apago la pantalla.
   - d) Pido a un compañero que lo vigile.
8. Una visita espera sola en la zona de trabajo. ¿Qué haces?
   - a) Nada.
   - b) La acompaño o aviso a quien la espera.
   - c) Le doy la clave del Wi-Fi interno.
   - d) La dejo usar un equipo.
9. ¿Qué contraseña es mejor para un servicio corporativo?
   - a) La misma que uso en casa.
   - b) Una larga, única y guardada en el gestor autorizado.
   - c) El nombre de la empresa con un número.
   - d) Una nota pegada en el monitor.
10. Si comunico de buena fe un correo que resulta ser legítimo, ¿qué pasa?
    - a) Me sancionan.
    - b) No pasa nada: avisar siempre es correcto.
    - c) Me lo recuerdan en la reunión.
    - d) Se anota en mi expediente.

**Soluciones:** 1-c · 2-b · 3-c · 4-b · 5-c · 6-b · 7-b · 8-b · 9-b · 10-b

**Cómo se utiliza en la sesión (resumen para quien dirige la acción):** (1) 10 min: presentación de las cinco señales; (2) 20 min: los tres casos, por grupos, con la regla PARA-VERIFICA-AVISA; (3) 10 min: puesta en común y dudas; (4) 10 min: cuestionario individual; (5) 10 min: corrección y entrega de la guía impresa.

---

### 3.2. Vinculación con el programa

- **Objetivo relacionado:** O-01 (con apoyo en O-05)
- **Acción relacionada:** A-01 — Taller presencial «Reconoce y comunica»
- **Destinatarios:** todo el personal de Logisticfy, con casos adaptados a Atención al Cliente, Administración, Comercial y Operaciones; la persona en prácticas
- **Canal:** taller presencial de 60 minutos; la guía se reparte impresa (una página) y se publica en el repositorio corporativo y por correo interno
- **Uso previsto:** se proyecta en el taller. Las secciones 2 y 3 se explican de forma guiada, los casos de la sección 5 se trabajan en grupos, el cuestionario mide el resultado del indicador de O-01 (apartado 2.3), y la guía queda como recordatorio en el puesto de trabajo.
- **Ubicación del archivo:** integrado en este documento (apartado 3.1); no hay archivos adjuntos

---

## 4. Fuentes, supuestos y autoría

### 4.1. Fuentes y recursos utilizados

| Fuente | Apartado | Información utilizada |
|---|---|---|
| [PE 90.1] Logisticfy | Descripción, organización, funcionamiento del negocio, sistemas, inventario de activos | Procesos, plantilla (20 personas), activos y sus ID, tres transportistas |
| [PE 90.1] Briefing, Actividades, Plantilla y Rúbrica | Todos | Estructura, requisitos y criterios de la entrega |
| Conocimiento general de buenas prácticas de seguridad | n. d. | Ideas habituales (mínimo privilegio, MFA, copias y restauración, phishing); redactadas con palabras propias y adaptadas a Logisticfy |

No se han utilizado datos personales reales ni credenciales. Todos los nombres de empresa del material son ficticios.

### 4.2. Supuestos y limitaciones

- **Supuesto:** existe un responsable de IT que puede actuar como coordinador y una persona de Dirección que firma las actas.
- **Supuesto:** los activos contienen datos de personas (contactos y destinatarios), como indica la documentación de forma genérica.
- **Desconocido:** no se conocen los controles técnicos actuales (MFA, cifrado, políticas de contraseñas), por lo que las normas se formulan como *propuestas*, sin afirmar incumplimientos.
- **Limitación:** la arquitectura es conceptual (sin IP, versiones ni configuraciones); la normativa no se apoya en configuraciones concretas.
- **Limitación:** los plazos del programa son relativos (semanas), pues no se fija una fecha de inicio. No se presentan resultados de concienciación.

### 4.3. Autoría y revisiones

El trabajo es de Volodymyr Osebchuk. **Decisiones propias:** el enfoque general, la elección del material M-01 y la revisión final de todo el contenido. **Apoyo utilizado:** asistente de IA (Claude, de Anthropic) para redactar y estructurar el borrador, que he revisado, adaptado y comprobado con la documentación *[PE 90.1] Logisticfy* (identificadores de activos y coherencia entre principios, normas, objetivos, acciones y material: P ↔ N ↔ O ↔ A ↔ M-01).
