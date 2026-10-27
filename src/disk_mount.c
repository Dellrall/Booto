/**
 * @file disk_mount.c
 * @brief Implementation of target storage discovery and forensic read-only mounter.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "disk_mount.h"
#include "logger.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

booto_error_t disk_exec_argv(const char *const argv[], const char *stdin_data, size_t stdin_len, int *exit_status) {
    if (exit_status) *exit_status = -1;
    if (!argv || !argv[0]) return BOOTO_ERR_INVALID_ARG;

    int pfd[2] = {-1, -1};
    if (stdin_data && pipe(pfd) != 0) return BOOTO_ERR_IO;

    pid_t pid = fork();
    if (pid < 0) {
        if (stdin_data) { close(pfd[0]); close(pfd[1]); }
        return BOOTO_ERR_GENERIC;
    }
    if (pid == 0) {
        if (stdin_data) {
            close(pfd[1]);
            if (dup2(pfd[0], STDIN_FILENO) < 0) _exit(126);
            close(pfd[0]);
        }
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    if (stdin_data) {
        close(pfd[0]);
        /* Ignore SIGPIPE so an early-exiting child only yields EPIPE here. */
        struct sigaction ign, old;
        memset(&ign, 0, sizeof(ign));
        ign.sa_handler = SIG_IGN;
        sigemptyset(&ign.sa_mask);
        sigaction(SIGPIPE, &ign, &old);
        size_t off = 0;
        while (off < stdin_len) {
            ssize_t w = write(pfd[1], stdin_data + off, stdin_len - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                break;
            }
            off += (size_t)w;
        }
        close(pfd[1]);
        sigaction(SIGPIPE, &old, NULL);
    }

    int status = 0;
    pid_t r;
    do {
        r = waitpid(pid, &status, 0);
    } while (r < 0 && errno == EINTR);
    if (r < 0) return BOOTO_ERR_GENERIC;

    if (!WIFEXITED(status)) return BOOTO_ERR_GENERIC;
    int code = WEXITSTATUS(status);
    if (exit_status) *exit_status = code;
    if (code == 0) return BOOTO_OK;
    if (code == 127) return BOOTO_ERR_NOT_FOUND;
    return BOOTO_ERR_GENERIC;
}

booto_error_t disk_exec_capture(const char *const argv[], const uint8_t *stdin_data, size_t stdin_len,
                                uint8_t **out, size_t *out_len, size_t max_out) {
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!argv || !argv[0] || !out || !out_len || (!stdin_data && stdin_len > 0)) return BOOTO_ERR_INVALID_ARG;

    int in_pfd[2], out_pfd[2];
    if (pipe(in_pfd) != 0) return BOOTO_ERR_IO;
    if (pipe(out_pfd) != 0) {
        close(in_pfd[0]); close(in_pfd[1]);
        return BOOTO_ERR_IO;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(in_pfd[0]); close(in_pfd[1]); close(out_pfd[0]); close(out_pfd[1]);
        return BOOTO_ERR_GENERIC;
    }
    if (pid == 0) {
        if (dup2(in_pfd[0], STDIN_FILENO) < 0 || dup2(out_pfd[1], STDOUT_FILENO) < 0) _exit(126);
        close(in_pfd[0]); close(in_pfd[1]); close(out_pfd[0]); close(out_pfd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }

    close(in_pfd[0]);
    close(out_pfd[1]);
    int wfd = in_pfd[1];
    int rfd = out_pfd[0];

    /* Ignore SIGPIPE so an early-exiting child only yields EPIPE here. */
    struct sigaction ign, old;
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGPIPE, &ign, &old);

    if (stdin_len == 0) {
        close(wfd);
        wfd = -1;
    } else {
        /* Non-blocking so a partial pipe never stalls us while the child waits for stdout to drain. */
        int fl = fcntl(wfd, F_GETFL);
        if (fl >= 0) fcntl(wfd, F_SETFL, fl | O_NONBLOCK);
    }

    size_t limit = max_out < SIZE_MAX ? max_out + 1 : SIZE_MAX;
    uint8_t *buf = NULL;
    size_t cap = 0, used = 0, woff = 0;
    booto_error_t err = BOOTO_OK;

    while (rfd >= 0) {
        struct pollfd pfds[2];
        nfds_t n = 0;
        pfds[n].fd = rfd; pfds[n].events = POLLIN; pfds[n].revents = 0; n++;
        if (wfd >= 0) { pfds[n].fd = wfd; pfds[n].events = POLLOUT; pfds[n].revents = 0; n++; }

        if (poll(pfds, n, -1) < 0) {
            if (errno == EINTR) continue;
            err = BOOTO_ERR_IO;
            break;
        }

        if (wfd >= 0 && pfds[1].revents) {
            ssize_t w = (pfds[1].revents & POLLOUT) ? write(wfd, stdin_data + woff, stdin_len - woff) : -1;
            if (w > 0) woff += (size_t)w;
            /* Child stopped reading (EPIPE/POLLERR): stop feeding; its exit status decides the outcome. */
            if (woff == stdin_len || (w < 0 && errno != EINTR && errno != EAGAIN) || !(pfds[1].revents & POLLOUT)) {
                close(wfd);
                wfd = -1;
            }
        }

        if (pfds[0].revents) {
            if (used == cap) {
                size_t ncap = cap == 0 ? 65536 : (cap > limit / 2 ? limit : cap * 2);
                if (ncap > limit) ncap = limit;
                uint8_t *nb = (uint8_t *)realloc(buf, ncap);
                if (!nb) {
                    err = BOOTO_ERR_OUT_OF_MEMORY;
                    break;
                }
                buf = nb;
                cap = ncap;
            }
            ssize_t r = read(rfd, buf + used, cap - used);
            if (r > 0) {
                used += (size_t)r;
                if (used > max_out) {
                    LOG_ERROR("'%s' output exceeds %zu byte limit; aborting (decompression bomb guard)", argv[0], max_out);
                    err = BOOTO_ERR_CORRUPT_DATA;
                    break;
                }
            } else if (r == 0) {
                close(rfd);
                rfd = -1;
            } else if (errno != EINTR && errno != EAGAIN) {
                err = BOOTO_ERR_IO;
                break;
            }
        }
    }

    if (wfd >= 0) close(wfd);
    if (rfd >= 0) close(rfd);
    if (err != BOOTO_OK) kill(pid, SIGKILL);

    int status = 0;
    pid_t wr;
    do {
        wr = waitpid(pid, &status, 0);
    } while (wr < 0 && errno == EINTR);
    sigaction(SIGPIPE, &old, NULL);

    if (err == BOOTO_OK) {
        if (wr < 0) err = BOOTO_ERR_GENERIC;
        else if (WIFEXITED(status) && WEXITSTATUS(status) == 127) err = BOOTO_ERR_NOT_FOUND;
        else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) err = BOOTO_ERR_CORRUPT_DATA;
    }
    if (err != BOOTO_OK) {
        free(buf);
        return err;
    }
    *out = buf;
    *out_len = used;
    return BOOTO_OK;
}

booto_error_t disk_ensure_private_dir(const char *path) {
    if (!path || !path[0]) return BOOTO_ERR_INVALID_ARG;
    if (mkdir(path, 0700) == 0) return BOOTO_OK;
    if (errno != EEXIST) {
        LOG_ERROR("Failed to create directory '%s': %s", path, strerror(errno));
        return BOOTO_ERR_IO;
    }
    struct stat st;
    if (lstat(path, &st) != 0) return BOOTO_ERR_IO;
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        LOG_ERROR("Refusing unsafe directory '%s' (symlink, foreign owner or group/world-writable)", path);
        return BOOTO_ERR_PERMISSION_DENIED;
    }
    return BOOTO_OK;
}

static bool valid_mapper_name(const char *name) {
    size_t n = strlen(name);
    if (n == 0 || n > 63) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!isalnum(c) && c != '_' && c != '-') return false;
    }
    return true;
}

bool disk_is_running_as_root(void) {
    return (geteuid() == 0);
}

const char *disk_format_size(uint64_t bytes, char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) return "";

    const char *units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    int unit_idx = 0;
    double size = (double)bytes;

    while (size >= 1024.0 && unit_idx < 5) {
        size /= 1024.0;
        unit_idx++;
    }

    if (unit_idx == 0) {
        snprintf(buf, buf_size, "%llu B", (unsigned long long)bytes);
    } else {
        snprintf(buf, buf_size, "%.1f %s", size, units[unit_idx]);
    }
    return buf;
}

static void trim_trailing_spaces(char *str) {
    if (!str) return;
    int len = (int)strlen(str);
    while (len > 0 && isspace((unsigned char)str[len - 1])) {
        str[len - 1] = '\0';
        len--;
    }
}

booto_error_t disk_probe_fs_magic(const char *dev_path, char *fs_buf, size_t fs_buf_size, char *label_buf, size_t label_buf_size) {
    if (!dev_path || !fs_buf || fs_buf_size == 0) return BOOTO_ERR_INVALID_ARG;
    fs_buf[0] = '\0';
    if (label_buf && label_buf_size > 0) label_buf[0] = '\0';

    char full_dev[256];
    if (dev_path[0] == '/') {
        snprintf(full_dev, sizeof(full_dev), "%s", dev_path);
    } else {
        snprintf(full_dev, sizeof(full_dev), "/dev/%s", dev_path);
    }

    int fd = open(full_dev, O_RDONLY);
    if (fd < 0) {
        return BOOTO_ERR_IO;
    }

    // 1. Probe Sector 0 (512 bytes): LUKS, XFS, NTFS, FAT
    uint8_t sec0[512];
    ssize_t n0 = pread(fd, sec0, sizeof(sec0), 0);
    if (n0 == (ssize_t)sizeof(sec0)) {
        // Check LUKS / LUKS2 container magic at offset 0 ("LUKS\xba\xbe")
        if (memcmp(sec0, "LUKS\xba\xbe", 6) == 0) {
            uint16_t luks_ver = (uint16_t)(((uint16_t)sec0[6] << 8) | (uint16_t)sec0[7]);
            snprintf(fs_buf, fs_buf_size, "crypto_LUKS");
            if (label_buf && label_buf_size > 0) {
                snprintf(label_buf, label_buf_size, (luks_ver == 2) ? "Encrypted Volume (LUKS2)" : "Encrypted Volume (LUKS1)");
            }
            close(fd);
            return BOOTO_OK;
        }

        // Check XFS at offset 0 ("XFSB")
        if (memcmp(sec0, "XFSB", 4) == 0) {
            snprintf(fs_buf, fs_buf_size, "xfs");
            if (label_buf && label_buf_size > 0) {
                snprintf(label_buf, label_buf_size, "%.12s", (const char *)&sec0[108]);
                trim_trailing_spaces(label_buf);
            }
            close(fd);
            return BOOTO_OK;
        }

        // Check NTFS at offset 3 ("NTFS    ")
        if (memcmp(&sec0[3], "NTFS    ", 8) == 0) {
            snprintf(fs_buf, fs_buf_size, "ntfs");
            close(fd);
            return BOOTO_OK;
        }

        // Check FAT / VFAT
        if (sec0[510] == 0x55 && sec0[511] == 0xAA) {
            if (memcmp(&sec0[54], "FAT12   ", 8) == 0 || memcmp(&sec0[54], "FAT16   ", 8) == 0) {
                snprintf(fs_buf, fs_buf_size, "vfat");
                if (label_buf && label_buf_size > 0) {
                    snprintf(label_buf, label_buf_size, "%.11s", (const char *)&sec0[43]);
                    trim_trailing_spaces(label_buf);
                }
                close(fd);
                return BOOTO_OK;
            }
            if (memcmp(&sec0[82], "FAT32   ", 8) == 0) {
                snprintf(fs_buf, fs_buf_size, "vfat");
                if (label_buf && label_buf_size > 0) {
                    snprintf(label_buf, label_buf_size, "%.11s", (const char *)&sec0[71]);
                    trim_trailing_spaces(label_buf);
                }
                close(fd);
                return BOOTO_OK;
            }
        }
    }

    // 2. Probe Ext2 / Ext3 / Ext4 at offset 1024 (magic 0xEF53 at byte 56 inside superblock)
    uint8_t ext_sb[1024];
    ssize_t n_ext = pread(fd, ext_sb, sizeof(ext_sb), 1024);
    if (n_ext == (ssize_t)sizeof(ext_sb)) {
        uint16_t magic = (uint16_t)((uint16_t)ext_sb[56] | (uint16_t)((uint16_t)ext_sb[57] << 8));
        if (magic == 0xEF53) {
            snprintf(fs_buf, fs_buf_size, "ext4");
            if (label_buf && label_buf_size > 0) {
                snprintf(label_buf, label_buf_size, "%.16s", (const char *)&ext_sb[120]);
                trim_trailing_spaces(label_buf);
            }
            close(fd);
            return BOOTO_OK;
        }
    }

    // 3. Probe ISO9660 at offset 32768 (32 KB, Volume Descriptor "CD001" at byte 1)
    uint8_t iso_buf[2048];
    ssize_t n_iso = pread(fd, iso_buf, sizeof(iso_buf), 32768);
    if (n_iso == (ssize_t)sizeof(iso_buf)) {
        if (memcmp(&iso_buf[1], "CD001", 5) == 0) {
            snprintf(fs_buf, fs_buf_size, "iso9660");
            if (label_buf && label_buf_size > 0) {
                snprintf(label_buf, label_buf_size, "%.32s", (const char *)&iso_buf[40]);
                trim_trailing_spaces(label_buf);
            }
            close(fd);
            return BOOTO_OK;
        }
    }

    // 4. Probe Btrfs at offset 65536 (64 KB, magic "_BHRfS_M" at byte 64)
    uint8_t btrfs_sb[1024];
    ssize_t n_btrfs = pread(fd, btrfs_sb, sizeof(btrfs_sb), 65536);
    if (n_btrfs == (ssize_t)sizeof(btrfs_sb)) {
        if (memcmp(&btrfs_sb[64], "_BHRfS_M", 8) == 0) {
            snprintf(fs_buf, fs_buf_size, "btrfs");
            if (label_buf && label_buf_size > 0) {
                snprintf(label_buf, label_buf_size, "%.255s", (const char *)&btrfs_sb[299]);
                trim_trailing_spaces(label_buf);
            }
            close(fd);
            return BOOTO_OK;
        }
    }

    close(fd);
    snprintf(fs_buf, fs_buf_size, "unknown");
    return BOOTO_OK;
}

static void add_mock_partitions(disk_discovery_result_t *result) {
    if (!result) return;

    if (result->count < MAX_DISCOVERED_PARTITIONS) {
        disk_partition_t *p = &result->partitions[result->count++];
        snprintf(p->dev_path, sizeof(p->dev_path), "/dev/nvme0n1p2");
        snprintf(p->name, sizeof(p->name), "nvme0n1p2");
        p->size_bytes = 482575360ULL * 1024ULL;
        disk_format_size(p->size_bytes, p->size_str, sizeof(p->size_str));
        snprintf(p->fs_type, sizeof(p->fs_type), "ext4");
        snprintf(p->label, sizeof(p->label), "Ubuntu 22.04 LTS (Target)");
        snprintf(p->uuid, sizeof(p->uuid), "e4a2c1f9-90b1-4f8a-a92c-8123ef459a01");
        p->is_target = true;
        p->is_mounted_ro = false;
        p->is_removable = false;
    }

    if (result->count < MAX_DISCOVERED_PARTITIONS) {
        disk_partition_t *p = &result->partitions[result->count++];
        snprintf(p->dev_path, sizeof(p->dev_path), "/dev/nvme0n1p1");
        snprintf(p->name, sizeof(p->name), "nvme0n1p1");
        p->size_bytes = 999424ULL * 1024ULL;
        disk_format_size(p->size_bytes, p->size_str, sizeof(p->size_str));
        snprintf(p->fs_type, sizeof(p->fs_type), "vfat");
        snprintf(p->label, sizeof(p->label), "EFI System Partition");
        snprintf(p->uuid, sizeof(p->uuid), "B849-1A2E");
        p->is_target = false;
        p->is_mounted_ro = false;
        p->is_removable = false;
    }

    if (result->count < MAX_DISCOVERED_PARTITIONS) {
        disk_partition_t *p = &result->partitions[result->count++];
        snprintf(p->dev_path, sizeof(p->dev_path), "/dev/sda1");
        snprintf(p->name, sizeof(p->name), "sda1");
        p->size_bytes = 976760832ULL * 1024ULL;
        disk_format_size(p->size_bytes, p->size_str, sizeof(p->size_str));
        snprintf(p->fs_type, sizeof(p->fs_type), "ntfs");
        snprintf(p->label, sizeof(p->label), "Data Archive");
        snprintf(p->uuid, sizeof(p->uuid), "7A4C89E14C899723");
        p->is_target = false;
        p->is_mounted_ro = false;
        p->is_removable = false;
    }
}

booto_error_t disk_discover_partitions(disk_discovery_result_t *result, bool include_mock) {
    if (!result) return BOOTO_ERR_INVALID_ARG;
    memset(result, 0, sizeof(*result));

    FILE *fp = fopen("/proc/partitions", "r");
    if (!fp) {
        LOG_WARN("Unable to open /proc/partitions");
        if (include_mock) add_mock_partitions(result);
        return BOOTO_OK;
    }

    char line[256];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        if (include_mock) add_mock_partitions(result);
        return BOOTO_OK;
    }

    while (fgets(line, sizeof(line), fp) && result->count < MAX_DISCOVERED_PARTITIONS) {
        int major, minor;
        unsigned long long blocks;
        char name[32];

        if (sscanf(line, "%d %d %llu %31s", &major, &minor, &blocks, name) == 4) {
            if (strncmp(name, "loop", 4) == 0 || strncmp(name, "ram", 3) == 0) {
                continue;
            }

            disk_partition_t *p = &result->partitions[result->count];
            snprintf(p->name, sizeof(p->name), "%s", name);
            snprintf(p->dev_path, sizeof(p->dev_path), "/dev/%s", name);
            p->size_bytes = blocks * 1024ULL;
            disk_format_size(p->size_bytes, p->size_str, sizeof(p->size_str));

            // Direct Superblock Magic Probing
            char probed_fs[32] = {0};
            char probed_label[64] = {0};

            booto_error_t probe_err = disk_probe_fs_magic(p->dev_path, probed_fs, sizeof(probed_fs), probed_label, sizeof(probed_label));
            if (probe_err == BOOTO_OK) {
                snprintf(p->fs_type, sizeof(p->fs_type), "%s", probed_fs);
                if (probed_label[0] != '\0') {
                    snprintf(p->label, sizeof(p->label), "%s", probed_label);
                } else {
                    if (strcmp(probed_fs, "vfat") == 0) {
                        snprintf(p->label, sizeof(p->label), "EFI / System Volume");
                    } else if (strcmp(probed_fs, "ext4") == 0) {
                        snprintf(p->label, sizeof(p->label), "Linux Rootfs");
                    } else if (strcmp(probed_fs, "crypto_LUKS") == 0) {
                        snprintf(p->label, sizeof(p->label), "Encrypted Volume (LUKS)");
                    } else if (strcmp(probed_fs, "xfs") == 0 || strcmp(probed_fs, "btrfs") == 0) {
                        snprintf(p->label, sizeof(p->label), "Linux Filesystem");
                    } else {
                        snprintf(p->label, sizeof(p->label), "Storage Volume");
                    }
                }

                if (strcmp(probed_fs, "ext4") == 0 || strcmp(probed_fs, "xfs") == 0 ||
                    strcmp(probed_fs, "btrfs") == 0 || strcmp(probed_fs, "crypto_LUKS") == 0) {
                    p->is_target = true;
                }
            } else {
                // Device unreadable (e.g. non-root): name-based guess only for explicit pN partition suffixes
                size_t nlen = strlen(name);
                bool part_suffix = nlen >= 2 && name[nlen - 2] == 'p' && isdigit((unsigned char)name[nlen - 1]);
                if (strstr(name, "efi") || (part_suffix && name[nlen - 1] == '1')) {
                    snprintf(p->fs_type, sizeof(p->fs_type), "vfat");
                    snprintf(p->label, sizeof(p->label), "ESP / Boot");
                } else if (part_suffix && name[nlen - 1] == '2') {
                    snprintf(p->fs_type, sizeof(p->fs_type), "ext4");
                    snprintf(p->label, sizeof(p->label), "Linux Rootfs");
                    p->is_target = true;
                } else {
                    snprintf(p->fs_type, sizeof(p->fs_type), "unknown");
                    snprintf(p->label, sizeof(p->label), "Storage Volume");
                }
            }

            p->is_mounted_ro = false;
            result->count++;
        }
    }

    fclose(fp);

    if (include_mock) add_mock_partitions(result);

    // Guarantee default target selection
    if (result->count > 0) {
        bool has_target = false;
        int largest_idx = 0;
        uint64_t max_size = 0;
        for (int i = 0; i < result->count; i++) {
            if (result->partitions[i].is_target) {
                has_target = true;
                break;
            }
            if (result->partitions[i].size_bytes > max_size) {
                max_size = result->partitions[i].size_bytes;
                largest_idx = i;
            }
        }
        if (!has_target && result->count > 0) {
            result->partitions[largest_idx].is_target = true;
        }
    }

    LOG_INFO("Discovered %d storage block devices/partitions", result->count);
    return BOOTO_OK;
}

/* Journal/log replay options: a journaled fs must never be mounted without these. */
static const char *fs_noreplay_opts(const char *fs) {
    if (strcmp(fs, "ext4") == 0 || strcmp(fs, "ext3") == 0) return "noload";
    if (strcmp(fs, "xfs") == 0) return "norecovery";
    if (strcmp(fs, "btrfs") == 0) return "nologreplay";
    return NULL;
}

static void build_dev_path(const char *dev_path, char *out, size_t out_size) {
    if (dev_path[0] == '/') {
        snprintf(out, out_size, "%.255s", dev_path);
    } else {
        snprintf(out, out_size, "/dev/%.250s", dev_path);
    }
}

booto_error_t disk_mount_ro(const char *dev_path, const char *mount_point, const char *fs_type) {
    if (!dev_path || !mount_point) return BOOTO_ERR_INVALID_ARG;

    char full_dev[256];
    build_dev_path(dev_path, full_dev, sizeof(full_dev));

    LOG_INFO("Attempting forensic read-only mount: %s -> %s", full_dev, mount_point);

    if (!disk_is_running_as_root()) {
        LOG_ERROR("Read-only mount of %s requires root privileges", full_dev);
        return BOOTO_ERR_PERMISSION_DENIED;
    }

    booto_error_t dir_err = disk_ensure_private_dir(mount_point);
    if (dir_err != BOOTO_OK) return dir_err;

    // Block-level RO flag: MS_RDONLY alone does not stop the kernel writing to the evidence device.
    int fd = open(full_dev, O_RDONLY | O_CLOEXEC);
    int one = 1;
    if (fd < 0 || ioctl(fd, BLKROSET, &one) != 0) {
        LOG_ERROR("Failed to set block device %s read-only (BLKROSET): %s", full_dev, strerror(errno));
        if (fd >= 0) close(fd);
        return BOOTO_ERR_IO;
    }
    close(fd);

    unsigned long flags = MS_RDONLY | MS_NODEV | MS_NOEXEC | MS_NOSUID;

    // If specific filesystem requested
    if (fs_type && strlen(fs_type) > 0 && strcmp(fs_type, "unknown") != 0) {
        if (mount(full_dev, mount_point, fs_type, flags, fs_noreplay_opts(fs_type)) == 0) {
            LOG_INFO("Successfully mounted %s at %s (%s) strictly READ-ONLY", full_dev, mount_point, fs_type);
            return BOOTO_OK;
        }
    }

    // Try common filesystems for unknown/auto detection
    const char *candidate_fs[] = {"ext4", "vfat", "ntfs", "iso9660", "btrfs", "xfs"};
    size_t num_fs = sizeof(candidate_fs) / sizeof(candidate_fs[0]);

    for (size_t i = 0; i < num_fs; i++) {
        if (mount(full_dev, mount_point, candidate_fs[i], flags, fs_noreplay_opts(candidate_fs[i])) == 0) {
            LOG_INFO("Successfully mounted %s at %s (%s) strictly READ-ONLY", full_dev, mount_point, candidate_fs[i]);
            return BOOTO_OK;
        }
    }

    // If all fail, the disk is an unformatted or raw partition table (e.g. fresh VM disk)
    LOG_WARN("%s could not be mounted read-only (no supported filesystem). Direct raw sector inspection is still possible.", full_dev);
    return BOOTO_ERR_MOUNT_FAILED;
}

booto_error_t disk_unmount(const char *mount_point) {
    if (!mount_point) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Unmounting %s...", mount_point);

    if (!disk_is_running_as_root()) {
        LOG_ERROR("Unmount of %s requires root privileges", mount_point);
        return BOOTO_ERR_PERMISSION_DENIED;
    }

    if (umount2(mount_point, MNT_DETACH) != 0) {
        LOG_ERROR("Failed to unmount %s: %s", mount_point, strerror(errno));
        return BOOTO_ERR_IO;
    }

    LOG_INFO("Cleanly unmounted %s", mount_point);
    return BOOTO_OK;
}

booto_error_t disk_luks_open_ro(const char *dev_path, const char *mapper_name, const char *passphrase) {
    if (!dev_path || !mapper_name) return BOOTO_ERR_INVALID_ARG;
    if (!valid_mapper_name(mapper_name)) {
        LOG_ERROR("Invalid LUKS mapper name (allowed: [A-Za-z0-9_-]{1,63})");
        return BOOTO_ERR_INVALID_ARG;
    }

    char full_dev[256];
    build_dev_path(dev_path, full_dev, sizeof(full_dev));

    LOG_INFO("Attempting forensic read-only LUKS open: %s -> /dev/mapper/%s", full_dev, mapper_name);

    if (!disk_is_running_as_root()) {
        LOG_ERROR("LUKS unlock of %s requires root privileges", full_dev);
        return BOOTO_ERR_PERMISSION_DENIED;
    }

    const char *pass = passphrase ? passphrase : "";
    const char *const argv[] = {"cryptsetup", "open", "--readonly", "--key-file=-", full_dev, mapper_name, NULL};
    int status = -1;
    booto_error_t err = disk_exec_argv(argv, pass, strlen(pass), &status);
    if (err == BOOTO_OK) {
        LOG_INFO("Successfully unlocked LUKS volume '%s' as /dev/mapper/%s (READ-ONLY)", full_dev, mapper_name);
        return BOOTO_OK;
    }
    if (err == BOOTO_ERR_GENERIC && status == 2) {
        LOG_ERROR("Failed to unlock LUKS volume '%s': Invalid passphrase", full_dev);
        return BOOTO_ERR_PERMISSION_DENIED;
    }
    LOG_ERROR("Failed to unlock LUKS volume '%s' (cryptsetup exit %d)", full_dev, status);
    return BOOTO_ERR_IO;
}

booto_error_t disk_luks_close(const char *mapper_name) {
    if (!mapper_name) return BOOTO_ERR_INVALID_ARG;
    if (!valid_mapper_name(mapper_name)) return BOOTO_ERR_INVALID_ARG;

    LOG_INFO("Closing LUKS mapper device /dev/mapper/%s...", mapper_name);

    if (!disk_is_running_as_root()) {
        LOG_ERROR("Closing LUKS mapper %s requires root privileges", mapper_name);
        return BOOTO_ERR_PERMISSION_DENIED;
    }

    const char *const argv[] = {"cryptsetup", "close", mapper_name, NULL};
    if (disk_exec_argv(argv, NULL, 0, NULL) != BOOTO_OK) {
        LOG_WARN("Failed to close LUKS mapper device '%s'", mapper_name);
        return BOOTO_ERR_IO;
    }

    return BOOTO_OK;
}

/* ---- ESP discovery (GPT / MBR) ---- */

static const uint8_t ESP_TYPE_GUID[16] = {0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11,
                                          0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B};
#define GPT_MAX_ENTRIES   1024u
#define GPT_MAX_READ      (1024u * 1024u)

static uint32_t esp_crc32(const uint8_t *p, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

static uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd_le64(const uint8_t *p) {
    return (uint64_t)rd_le32(p) | ((uint64_t)rd_le32(p + 4) << 32);
}

static bool has_gpt_sig(const uint8_t *buf, size_t len, uint32_t ss) {
    return ss >= 512 && len >= (size_t)ss * 2 && memcmp(buf + ss, "EFI PART", 8) == 0;
}

/* Validates the GPT header at LBA 1 and returns entry-array location; does not need the array itself. */
static booto_error_t gpt_header(const uint8_t *buf, uint32_t ss, uint64_t *arr_off, uint32_t *count, uint32_t *esize) {
    const uint8_t *h = buf + ss;
    uint32_t hsize = rd_le32(h + 12);
    if (hsize < 92 || hsize > ss) return BOOTO_ERR_CORRUPT_DATA;
    uint8_t tmp[4096];
    if (hsize > sizeof(tmp)) return BOOTO_ERR_CORRUPT_DATA;
    memcpy(tmp, h, hsize);
    memset(tmp + 16, 0, 4);
    if (esp_crc32(tmp, hsize) != rd_le32(h + 16)) return BOOTO_ERR_CORRUPT_DATA;
    uint64_t lba = rd_le64(h + 72);
    *count = rd_le32(h + 80);
    *esize = rd_le32(h + 84);
    if (*count > GPT_MAX_ENTRIES || *esize < 128 || *esize % 8 != 0 || *esize > 4096) return BOOTO_ERR_CORRUPT_DATA;
    if (lba > GPT_MAX_READ / ss) return BOOTO_ERR_CORRUPT_DATA;
    *arr_off = lba * ss;
    return BOOTO_OK;
}

booto_error_t disk_parse_esp_partitions(const uint8_t *buf, size_t len, uint32_t sector_size,
                                        uint32_t *part_numbers, int max, int *n) {
    if (!buf || !part_numbers || !n || max < 0 || sector_size < 512 || sector_size > 65536) return BOOTO_ERR_INVALID_ARG;
    *n = 0;
    if (has_gpt_sig(buf, len, sector_size)) {
        uint64_t off;
        uint32_t count, esize;
        booto_error_t err = gpt_header(buf, sector_size, &off, &count, &esize);
        if (err != BOOTO_OK) return err;
        size_t arr = (size_t)count * esize;
        if (off > len || arr > len - (size_t)off) return BOOTO_ERR_CORRUPT_DATA;
        const uint8_t *e = buf + off;
        if (esp_crc32(e, arr) != rd_le32(buf + sector_size + 88)) return BOOTO_ERR_CORRUPT_DATA;
        for (uint32_t i = 0; i < count && *n < max; i++) {
            if (memcmp(e + (size_t)i * esize, ESP_TYPE_GUID, 16) == 0) part_numbers[(*n)++] = i + 1;
        }
        return BOOTO_OK;
    }
    if (len < 512 || buf[510] != 0x55 || buf[511] != 0xAA) return BOOTO_OK;
    for (uint32_t i = 0; i < 4; i++) {
        uint8_t type = buf[446 + 16 * i + 4];
        if (type == 0xEE) { *n = 0; return BOOTO_ERR_CORRUPT_DATA; }
        if (type == 0xEF && *n < max) part_numbers[(*n)++] = i + 1;
    }
    return BOOTO_OK;
}

booto_error_t disk_find_esp_partitions(const char *disk_path, uint32_t *part_numbers, int max, int *n) {
    if (!disk_path || !part_numbers || !n || max < 0) return BOOTO_ERR_INVALID_ARG;
    *n = 0;
    int fd = open(disk_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) return BOOTO_ERR_PERMISSION_DENIED;
        if (errno == ENOENT || errno == ENOTDIR) return BOOTO_ERR_NOT_FOUND;
        return BOOTO_ERR_IO;
    }
    uint32_t ss = 0;
    struct stat st;
    int bss = 0;
    if (fstat(fd, &st) == 0 && S_ISBLK(st.st_mode) && ioctl(fd, BLKSSZGET, &bss) == 0 && bss >= 512 && bss <= 65536)
        ss = (uint32_t)bss;

    /* Probe LBA 0..1 at the known size, else at 512 then 4096 (images have no BLKSSZGET). */
    uint8_t *buf = malloc(GPT_MAX_READ);
    if (!buf) { close(fd); return BOOTO_ERR_OUT_OF_MEMORY; }
    ssize_t got = pread(fd, buf, 8192, 0);
    if (got < 0) { free(buf); close(fd); return BOOTO_ERR_IO; }
    size_t len = (size_t)got;
    if (ss == 0) ss = (!has_gpt_sig(buf, len, 512) && has_gpt_sig(buf, len, 4096)) ? 4096 : 512;
    if (len > (size_t)ss * 2) len = (size_t)ss * 2;

    booto_error_t err = BOOTO_OK;
    if (has_gpt_sig(buf, len, ss)) {
        uint64_t off;
        uint32_t count, esize;
        err = gpt_header(buf, ss, &off, &count, &esize);
        if (err == BOOTO_OK) {
            uint64_t need = off + (uint64_t)count * esize;
            if (need > GPT_MAX_READ) {
                err = BOOTO_ERR_CORRUPT_DATA;
            } else if (need > len) {
                got = pread(fd, buf + len, (size_t)need - len, (off_t)len);
                if (got < 0) err = BOOTO_ERR_IO;
                else len += (size_t)got;
            }
        }
    }
    if (err == BOOTO_OK) err = disk_parse_esp_partitions(buf, len, ss, part_numbers, max, n);
    free(buf);
    close(fd);
    return err;
}

/* "/dev/<name>" -> name, rejecting path tricks. */
static booto_error_t dev_name(const char *dev, const char **name) {
    if (!dev || strncmp(dev, "/dev/", 5) != 0) return BOOTO_ERR_INVALID_ARG;
    const char *nm = dev + 5;
    if (*nm == '\0' || strchr(nm, '/') || strstr(nm, "..")) return BOOTO_ERR_INVALID_ARG;
    *name = nm;
    return BOOTO_OK;
}

static bool read_partition_number(const char *dir, uint32_t *num) {
    char p[PATH_MAX];
    if (snprintf(p, sizeof(p), "%s/partition", dir) >= (int)sizeof(p)) return false;
    FILE *f = fopen(p, "re");
    if (!f) return false;
    unsigned long v = 0;
    int ok = fscanf(f, "%lu", &v);
    fclose(f);
    if (ok != 1 || v > UINT32_MAX) return false;
    *num = (uint32_t)v;
    return true;
}

booto_error_t disk_partition_parent(const char *part_dev, char *parent, size_t parent_size) {
    // A path outside /dev (e.g. a disk image file) has no sysfs entry: it is a whole disk, not a partition.
    if (part_dev && strncmp(part_dev, "/dev/", 5) != 0) return BOOTO_ERR_NOT_FOUND;
    const char *nm;
    booto_error_t err = dev_name(part_dev, &nm);
    if (err != BOOTO_OK) return err;
    if (!parent || parent_size == 0) return BOOTO_ERR_INVALID_ARG;
    char link[PATH_MAX], resolved[PATH_MAX];
    if (snprintf(link, sizeof(link), "/sys/class/block/%s", nm) >= (int)sizeof(link)) return BOOTO_ERR_INVALID_ARG;
    uint32_t num;
    if (!realpath(link, resolved) || !read_partition_number(resolved, &num)) return BOOTO_ERR_NOT_FOUND;
    char *slash = strrchr(resolved, '/');
    if (!slash || slash == resolved) return BOOTO_ERR_NOT_FOUND;
    *slash = '\0';
    const char *pname = strrchr(resolved, '/');
    pname = pname ? pname + 1 : resolved;
    if (*pname == '\0') return BOOTO_ERR_NOT_FOUND;
    if (snprintf(parent, parent_size, "/dev/%s", pname) >= (int)parent_size) return BOOTO_ERR_INVALID_ARG;
    return BOOTO_OK;
}

booto_error_t disk_partition_by_number(const char *disk_dev, uint32_t number, char *out, size_t out_size) {
    const char *nm;
    booto_error_t err = dev_name(disk_dev, &nm);
    if (err != BOOTO_OK) return err;
    if (!out || out_size == 0) return BOOTO_ERR_INVALID_ARG;
    char dir[PATH_MAX];
    if (snprintf(dir, sizeof(dir), "/sys/class/block/%s", nm) >= (int)sizeof(dir)) return BOOTO_ERR_INVALID_ARG;
    DIR *d = opendir(dir);
    if (!d) return BOOTO_ERR_NOT_FOUND;
    err = BOOTO_ERR_NOT_FOUND;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char child[PATH_MAX];
        uint32_t num;
        if (snprintf(child, sizeof(child), "%s/%s", dir, de->d_name) >= (int)sizeof(child)) continue;
        if (read_partition_number(child, &num) && num == number) {
            err = snprintf(out, out_size, "/dev/%s", de->d_name) >= (int)out_size ? BOOTO_ERR_INVALID_ARG : BOOTO_OK;
            break;
        }
    }
    closedir(d);
    return err;
}
