package likelion.ideateam3.happy_board.service.member;

import likelion.ideateam3.happy_board.domain.member.Member;
import likelion.ideateam3.happy_board.domain.member.dto.LoginRequest;
import likelion.ideateam3.happy_board.domain.member.dto.LoginResponse;
import likelion.ideateam3.happy_board.domain.member.dto.SignUpRequest;
import likelion.ideateam3.happy_board.jwt.TokenProvider;
import likelion.ideateam3.happy_board.repository.member.MemberRepository;
import likelion.ideateam3.happy_board.response.exception.BusinessException;
import likelion.ideateam3.happy_board.response.exception.ExceptionType;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Service
public class MemberService {
    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;

    @Transactional
    public void signUp(SignUpRequest request) {
        // email 중복 확인
        memberRepository.findByEmail(request.getEmail())
                .ifPresent(it -> {
                    throw new BusinessException(ExceptionType.DUPLICATED_EMAIL);
                });

        // nickname 중복 확인
        memberRepository.findByNickname(request.getNickname())
                .ifPresent(it -> {
                    throw new BusinessException(ExceptionType.DUPLICATED_NICKNAME);
                });

        // DB 저장
        Member newMember = SignUpRequest.toEntity(request.getEmail(), passwordEncoder.encode(request.getPassword()), request.getName(), request.getNickname());
        memberRepository.save(newMember);
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        // DB에 해당 회원이 존재하는지 검사
        Member savedMember = memberRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BusinessException(ExceptionType.MEMBER_NOT_FOUND));

        // 비밀번호 검사
        if (!passwordEncoder.matches(request.getPassword(), savedMember.getPassword())) {
            throw new BusinessException(ExceptionType.PASSWORD_INVALID);
        }

        // 토큰 발급
        String token = tokenProvider.createToken(savedMember.getEmail(), savedMember.getRole());
        return new LoginResponse(token, savedMember.getNickname());
    }
}
