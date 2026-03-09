import Foundation
import UserNotifications

class RenewalManager {
    static let shared = RenewalManager()

    func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    func scheduleRenewalNotification(for app: SignedApp) {
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [app.id.uuidString])

        guard let triggerDate = Calendar.current.date(byAdding: .day, value: 6, to: app.signedDate),
              triggerDate > Date() else { return }

        let content = UNMutableNotificationContent()
        content.title = "\(app.name) expires tomorrow"
        content.body = "Open FlareSign to resign it before it stops working."
        content.sound = .default

        let components = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute], from: triggerDate)
        let trigger = UNCalendarNotificationTrigger(dateMatching: components, repeats: false)
        center.add(UNNotificationRequest(identifier: app.id.uuidString, content: content, trigger: trigger))
    }

    func cancelRenewalNotification(for app: SignedApp) {
        UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: [app.id.uuidString])
    }

    func scheduleAllRenewalNotifications(apps: [SignedApp]) {
        apps.forEach { scheduleRenewalNotification(for: $0) }
    }
}
