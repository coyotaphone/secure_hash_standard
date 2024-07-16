# secure_hash_standard
SHS C library implementation according to NIST FIPS 180-4

Об'єкти структур SHA створюються відповідними функціями CreateSHA (повертає true якщо об'єкт успішно створено) та вимагають звільнення пам'яті по закінченню роботи з ними через DestroySHA

Повний вміст повідомлення не зберігається безпосередньо в об'єктах структур, а перебуває у вигляді постійно відкритого незакінченого дайджесту (хешу), фінальну версію якого можна отримати через SnapshotSHA, після чого об'єкти структури й надалі залишатимуться відкритими для запису

Об'єкти структури доступні для повторного використання завдяки ResetSHA, що обнуляє контекст, приводячи відкритий хеш до початкового стану

WriteSHA записує в повідомлення послідовність бітів bitv у режимі 'append' для забезпечення можливості запису навіть надмірного обсягу даних за необхідну кількість послідовних викликів функції (зручно, наприклад, використовувати при читанні з потоку); повертає true у випадках, коли повідомлення доповнено принаймні на один біт (false - якщо розрахована довжина повідомлення перевищує допустиму, або при нульовому bitc)

bitv - послідовність бітів від старшого до молодшого біта зліва направо (такий собі бітовий Big-Endian), влаштована у байтах від молодшого до найстаршого, вирівняних по лівому краю, отже останній байт автоматично вважається padded справа будь-якими бітами у сумарній кількості, якої бракує до 8 бітів; отже записується саме послідовність бітів, а не двійкові числа
