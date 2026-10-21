# Beavizor test yayını

Bu paket yalnızca sınırlı test içindir. Herkese açık üretim yayını değildir.

- Render planı: Free. Otomatik dağıtım kapalıdır.
- Test erişimi: kullanıcı adı `beavizor`, şifre Render tarafından üretilen `TEST_ACCESS_PASSWORD` değeridir.
- `/healthz` yalnızca sunucu durumunu verir; diğer yollar test şifresi ister.
- E-posta bağlantıları gerçek e-posta yerine özel sunucu kayıtlarına yazılır. Gerçek müşteri verisi kullanmayın.
- SQLite verileri geçicidir; yeniden başlatma/yayın sırasında kaybolabilir. Bu kurulum kalıcı müşteri kullanımı için uygun değildir.
- Üretim öncesi kalıcı veritabanı, SMTP, hız sınırlama, üretim sunucusu ve güvenlik incelemesi gerekir.
- Bu ortamda Ruby bulunmadığından Ruby çalışma testi henüz yapılamadı. Render derlemesi ve uçtan uca kontroller tamamlanmadan test başarılı sayılmamalıdır.

Kaynak ZIP sekiz dosya içeriyordu; `.env`, kişisel veritabanı veya gömülü erişim anahtarı bulunmadı. Gerçek sırlar yalnızca Render ortam değişkenlerinde tutulmalıdır.
