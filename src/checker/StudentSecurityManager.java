/*
 * Copyright 2014 Sander Verdonschot <sander.verdonschot at gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package checker;

import java.io.FileDescriptor;
import java.io.FilePermission;
import java.net.InetAddress;
import java.nio.file.Path;
import java.security.AccessControlException;
import java.security.Permission;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 *
 * @author Sander Verdonschot <sander.verdonschot at gmail.com>
 */
public class StudentSecurityManager extends SecurityManager {

    private final static Map<String, List<Class>> allowedActions = new HashMap<>();
    private final Set<String> accessibleLibraries = new HashSet<>(Arrays.asList());

    static {
        allowedActions.put("setSecurityManager", Arrays.asList(System.class, System.class, StudentSecurityManager.class));
        allowedActions.put("stopThread", Arrays.asList(Thread.class, AtomicTest.class));
    }

    private final Checker checker;
    private final int secretHash; // The "password" to disable the security manager

    StudentSecurityManager(Checker checker, SharedSecret secret) {
        this.checker = checker;
        secretHash = secret.hashCode();
    }

    /**
     * Disables the security manager.
     *
     * @param secret the key that was used when creating this SecurityManager
     */
    void disable(SharedSecret secret) {
        if (secret != null && secretHash == secret.hashCode()) {
            System.setSecurityManager(null);
        } else {
            reportException(new SecurityException("Attempt to disable the security manager."));
        }
    }

    @Override
    public void checkExit(int code) {
        throw new ExitTrappedException();
    }

    @Override
    public void checkPermission(Permission perm) {
        if (perm instanceof FilePermission) {
            FilePermission fp = (FilePermission) perm;

            if (fp.getActions().contains("read")) {
                checkRead(fp.getName());
            }
            if (fp.getActions().contains("write")) {
                checkWrite(fp.getName());
            }
            if (fp.getActions().contains("delete")) {
                checkDelete(fp.getName());
            }
            if (fp.getActions().contains("execute")) {
                checkExec(fp.getName());
            }

            return;
        } else if (allowedActions.containsKey(perm.getName())) {
            List<Class> expectedStack = allowedActions.get(perm.getName());
            Class[] stack = getClassContext();

            for (int i = 0; i < expectedStack.size(); i++) {
                if (i + 1 >= stack.length || stack[i + 1] != expectedStack.get(i)) {
                    reportException(new SecurityException("checkPermission: perm=" + perm.toString() + " name=" + perm.getName()));
                }
            }

            // The caller is as we expect - allow
            return;
        }

        reportException(new SecurityException("checkPermission: perm=" + perm.toString() + " name=" + perm.getName()));
    }

    @Override
    public void checkDelete(String file) {
        // Don't allow deletion of any files
        reportException(new AccessControlException("Deletion of file \"" + file + "\" denied."));
    }

    @Override
    public void checkRead(String file) {
        // Allow reading from the readable directories
        for (Path dir : checker.getReadDirectories()) {
            if (file.startsWith(dir.toString())) {
                // allow
                return;
            }
        }

        // Java files. The classloader looks in various places, but handles SecurityExceptions just fine.
        if (file.endsWith(".class") || file.endsWith(".jar") || file.endsWith(".properties")) {
            // Don't allow, but don't report either
            throw new AccessControlException("Read access to file \"" + file + "\" denied.");
        }

        // Don't allow access to any other part of the system
        reportException(new AccessControlException("Read access to file \"" + file + "\" denied."));
    }

    @Override
    public void checkWrite(String file) {
        // Allow writing to files in the writable directories
        for (Path dir : checker.getWriteDirectories()) {
            if (file.startsWith(dir.toString())) {
                // allow
                return;
            }
        }

        // Don't allow access to any other part of the system
        reportException(new AccessControlException("Write access to file \"" + file + "\" denied."));
    }

    @Override
    public void checkPropertyAccess(String key) {
        // There are too many of these that are required by various Java classes to function.
        // I also don't think allowing access to all of them is a large security risk.
    }

    @Override
    public void checkAccept(String host, int port) {
        reportException(new SecurityException("checkAccept: host=" + host + " port=" + port));
    }

    @Override
    public void checkConnect(String host, int port) {
        reportException(new SecurityException("checkConnect: host=" + host + " port=" + port));
    }

    @Override
    public void checkConnect(String host, int port, Object context) {
        reportException(new SecurityException("checkConnect: host=" + host + " port=" + port + " context=" + context));
    }

    @Override
    public void checkCreateClassLoader() {
        reportException(new SecurityException("checkCreateClassLoader"));
    }

    @Override
    public void checkExec(String cmd) {
        reportException(new SecurityException("Execution of file or command \"" + cmd + "\" denied."));
    }

    @Override
    public void checkLink(String lib) {
        if (accessibleLibraries.contains(lib) || lib.startsWith(System.getProperty("java.home"))) {
            // allow
            return;
        }

        reportException(new SecurityException("Access to library \"" + lib + "\" denied."));
    }

    @Override
    public void checkListen(int port) {
        reportException(new SecurityException("checkListen: port=" + port));
    }

    @Override
    public void checkMulticast(InetAddress maddr) {
        reportException(new SecurityException("checkMulticast: maddr=" + maddr));
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        reportException(new SecurityException("checkPermission: perm=" + perm + " context=" + context));
    }

    @Override
    public void checkPrintJobAccess() {
        reportException(new SecurityException("checkPrintJobAccess"));
    }

    @Override
    public void checkPropertiesAccess() {
        reportException(new SecurityException("checkPropertiesAccess"));
    }

    @Override
    public void checkRead(FileDescriptor fd) {
        reportException(new SecurityException("checkRead: fd=" + fd));
    }

    @Override
    public void checkRead(String file, Object context) {
        reportException(new SecurityException("checkRead: file=" + file + " context=" + context));
    }

    @Override
    public void checkSecurityAccess(String target) {
        reportException(new SecurityException("checkSecurityAccess: target=" + target));
    }

    @Override
    public void checkSetFactory() {
        reportException(new SecurityException("checkSetFactory"));
    }

    @Override
    public void checkWrite(FileDescriptor fd) {
        reportException(new SecurityException("checkWrite: fd=" + fd));
    }

    private void reportException(SecurityException se) {
        checker.securityBreach(se.getMessage());
        throw se;
    }

    static class ExitTrappedException extends SecurityException {
    }

    final static class SharedSecret {
        // This cannot be extended or overridden to change the hashCode implementation
    }
}
