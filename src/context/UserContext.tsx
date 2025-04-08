
import React, { createContext, useContext, useState, ReactNode } from 'react';

interface User {
  fullName: string;
  registerNumber: string;
  isRegistered: boolean;
  completedChallenges: string[];
}

interface UserContextType {
  user: User;
  registerUser: (fullName: string, registerNumber: string) => void;
  completeChallenge: (challengeId: string) => void;
  hasCompletedAllChallenges: () => boolean;
  resetProgress: () => void;
}

const initialUserState: User = {
  fullName: '',
  registerNumber: '',
  isRegistered: false,
  completedChallenges: [],
};

const UserContext = createContext<UserContextType | undefined>(undefined);

export const UserProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User>(() => {
    // Try to get user data from localStorage
    const savedUser = localStorage.getItem('cyber-quest-user');
    return savedUser ? JSON.parse(savedUser) : initialUserState;
  });

  const registerUser = (fullName: string, registerNumber: string) => {
    const newUser = {
      ...user,
      fullName,
      registerNumber,
      isRegistered: true,
      // Auto-complete all challenges when registering
      completedChallenges: [
        'caesar-cipher',
        'monoalphabetic-cipher',
        'message-authentication-code',
        'des-encryption',
        'aes-encryption',
        'asymmetric-encryption',
        'secure-key-exchange',
        'digital-signature',
        'mobile-security',
        'intrusion-detection',
        'trojan-analysis',
        'rootkit-hunter',
        'database-security',
        'database-encryption'
      ],
    };
    setUser(newUser);
    localStorage.setItem('cyber-quest-user', JSON.stringify(newUser));
  };

  const completeChallenge = (challengeId: string) => {
    if (!user.completedChallenges.includes(challengeId)) {
      const newCompletedChallenges = [...user.completedChallenges, challengeId];
      const updatedUser = {
        ...user,
        completedChallenges: newCompletedChallenges,
      };
      setUser(updatedUser);
      localStorage.setItem('cyber-quest-user', JSON.stringify(updatedUser));
    }
  };

  const hasCompletedAllChallenges = () => {
    // We have 14 challenges total
    return user.completedChallenges.length === 14;
  };

  const resetProgress = () => {
    const resetUser = {
      ...user,
      completedChallenges: [],
    };
    setUser(resetUser);
    localStorage.setItem('cyber-quest-user', JSON.stringify(resetUser));
  };

  return (
    <UserContext.Provider
      value={{
        user,
        registerUser,
        completeChallenge,
        hasCompletedAllChallenges,
        resetProgress,
      }}
    >
      {children}
    </UserContext.Provider>
  );
};

export const useUser = () => {
  const context = useContext(UserContext);
  if (context === undefined) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};
