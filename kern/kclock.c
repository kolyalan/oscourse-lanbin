/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <kern/kclock.h>
#include <kern/timer.h>
#include <kern/trap.h>
#include <kern/picirq.h>

static void
rtc_timer_init(void) {
  //pic_init();
  rtc_init();
}

static void
rtc_timer_pic_interrupt(void) {
  irq_setmask_8259A(irq_mask_8259A & ~(1 << IRQ_CLOCK));
}

static void
rtc_timer_pic_handle(void) {
  rtc_check_status();
  pic_send_eoi(IRQ_CLOCK);
}

struct Timer timer_rtc = {
    .timer_name        = "rtc",
    .timer_init        = rtc_timer_init,
    .enable_interrupts = rtc_timer_pic_interrupt,
    .handle_interrupts = rtc_timer_pic_handle,
};

void
rtc_init(void) {
  nmi_disable();
  // LAB 4: Your code here

  uint8_t A, B;

  outb(IO_RTC_CMND, RTC_AREG);
  A = inb(IO_RTC_DATA);
  A |= 0xF;
  outb(IO_RTC_DATA, A);

  outb(IO_RTC_CMND, RTC_BREG);
  B = inb(IO_RTC_DATA);
  B |= RTC_PIE;
  outb(IO_RTC_DATA, B);

	nmi_enable();
}

uint8_t
rtc_check_status(void) {
  uint8_t status = 0;
  // LAB 4: Your code here
  outb(IO_RTC_CMND, RTC_CREG);
  status = inb(IO_RTC_DATA);
  return status;
}
